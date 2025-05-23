/*
Análisis de Interfaces Físicas: Se han identificado múltiples interfaces físicas en estado down/down sin haber sido deshabilitadas administrativamente, lo cual representa un riesgo de seguridad con la posibilidad de conexiones no autorizadas.
Recomendaciones: Deshabilitar administrativamente todas las interfaces no utilizadas mediante el comando shutdown y asignarlas a una VLAN segura y no a la VLAN por defecto (VLAN 1).
*/

function analyzeConfig() {
    const fileInput = document.getElementById('configFile');
    const file = fileInput.files[0];
    const fileNameDisplay = document.getElementById('file-name');

    if (file) {
        fileNameDisplay.textContent = 'Archivo seleccionado: ' + file.name;
        const reader = new FileReader();

        reader.onload = function(event) {
            const configText = event.target.result;
            const analysisResults = analyzeCiscoConfig(configText);
            displayResults(analysisResults);
        }

        reader.readAsText(file);
    } else {
        alert('Please select a file.');
    }
}

// Add event listener for the export button after the DOM is fully loaded
document.addEventListener('DOMContentLoaded', (event) => {
    document.getElementById('export-report-btn').addEventListener('click', exportReport);
    document.getElementById('configFile').addEventListener('change', function() {
        const fileName = this.files[0]?.name;
        document.getElementById('file-name').textContent = fileName ? 'Archivo seleccionado: ' + fileName : '';
    });
});


function analyzeCiscoConfig(configText) {
    const compliant = [];
    const nonCompliant = [];

    // Detectar el tipo de sistema operativo
    let osType = 'IOS';
    if (configText.includes('Cisco IOS-XE Software')) {
        osType = 'IOS-XE';
    } else if (configText.includes('Cisco NX-OS Software')) {
        osType = 'NX-OS';
    }

    const radiusServerBlocks = configText.split(/(?=^radius server)/m).filter(block => block.trim().startsWith('radius server'));
    const radiusConfigured = radiusServerBlocks.length > 0;

    // Análisis específico por tipo de OS
    if (osType === 'IOS' || osType === 'IOS-XE') {
        // VTY Configuration - exec-timeout (Común en IOS y IOS-XE)
        const vtyLinesForTimeout = configText.split('\n').filter(line => line.trim().startsWith('line vty'));
        let timeoutConfigFound = false;

        for (const vtyLine of vtyLinesForTimeout) {
            const vtyRangeMatch = vtyLine.match(/line vty (\d+) (\d+)/);
            if (vtyRangeMatch) {
                const startVty = parseInt(vtyRangeMatch[1]);
                const endVty = parseInt(vtyRangeMatch[2]);

                const vtyBlockRegex = new RegExp(`line vty ${startVty} ${endVty}([\\s\\S]*?)(?:\\nline vty|\\n!|\\nend|$)`);
                const vtyBlockMatch = configText.match(vtyBlockRegex);

                if (vtyBlockMatch) {
                    const vtyBlock = vtyBlockMatch[1];
                    const timeoutMatch = vtyBlock.match(/exec-timeout (\d+) (\d+)/);

                    if (timeoutMatch) {
                        timeoutConfigFound = true;
                        const minutes = parseInt(timeoutMatch[1]);
                        const seconds = parseInt(timeoutMatch[2]);
                        const totalSeconds = (minutes * 60) + seconds;

                        if (totalSeconds > 600) { // 10 minutes = 600 seconds
                            nonCompliant.push({
                                severity: 'Media',
                                context: `${vtyLine.trim()}, ${timeoutMatch[0]}`,
                                recommendation: 'Configure un tiempo de espera de ejecución para las líneas VTY (máximo 10 minutos).',
                                solution: `${vtyLine.trim()}\n exec-timeout 10 0`,
                                description: `Las líneas VTY ${startVty}-${endVty} tienen un tiempo de espera de ejecución mayor a 10 minutos (${minutes}m ${seconds}s)`
                            });
                        } else {
                            compliant.push(`Las líneas VTY ${startVty}-${endVty} tienen un tiempo de espera de ejecución configurado (${minutes}m ${seconds}s)`);
                        }
                    } else {
                         nonCompliant.push({
                            severity: 'Media',
                            context: `${vtyLine.trim()}, sin exec-timeout`,
                            recommendation: 'Configure un tiempo de espera de ejecución para las líneas VTY (máximo 10 minutos).',
                            solution: `${vtyLine.trim()}\n exec-timeout 10 0`,
                            description: `Las líneas VTY ${startVty}-${endVty} no tienen un tiempo de espera de ejecución configurado`
                        });
                    }
                }
            }
        }

        // VTY Configuration - no line aux 0 (Común en IOS y IOS-XE)
        if (!configText.includes('no line aux 0')) {
            nonCompliant.push({
                severity: 'Media',
                context: 'Sin no line aux 0',
                recommendation: 'Deshabilite la línea auxiliar si no está en uso.',
                solution: 'no line aux 0',
                description: 'La línea auxiliar no está deshabilitada'
            });
        } else {
            compliant.push('La línea auxiliar está deshabilitada');
        }

        // Password and Encryption Configuration (Común en IOS y IOS-XE)
        const enableSecretMatch = configText.match(/enable secret (\d+)/);
        let enableSecretType = null;
        if (enableSecretMatch) {
            enableSecretType = parseInt(enableSecretMatch[1]);
        }

        if (configText.includes('enable secret 5 $1$') || enableSecretType === 5) {
            nonCompliant.push({
                severity: 'Alta',
                context: enableSecretType === 5 ? `enable secret ${enableSecretType}` : 'enable secret 5 $1$',
                recommendation: 'Utilice un algoritmo de cifrado más seguro como SHA256 (tipo 8) o SHA512 (tipo 9).',
                solution: 'enable secret sha256 <password>',
                description: 'Cifrado de enable secret débil (MD5, tipo 5)'
            });
        } else if (enableSecretType === 8) {
            compliant.push('El cifrado de enable secret es SHA256 (tipo 8)');
        } else if (enableSecretType === 9) {
            compliant.push('El cifrado de enable secret es SHA512 (tipo 9)');
        } else if (configText.includes('enable secret sha256')) {
             compliant.push('El cifrado de enable secret es SHA256');
        } else if (configText.includes('enable secret sha512')) {
             compliant.push('El cifrado de enable secret es SHA512');
        }
        else if (configText.includes('enable secret')) {
             nonCompliant.push({
                severity: 'Media',
                context: 'enable secret',
                recommendation: 'Configure el cifrado de enable secret con SHA256 (tipo 8) o SHA512 (tipo 9).',
                solution: 'enable secret sha256 <password>',
                description: 'El cifrado de enable secret no es SHA256, SHA512, tipo 8 o tipo 9'
            });
        } else {
            nonCompliant.push({
                severity: 'Alta',
                context: 'Sin enable secret',
                recommendation: 'Configure un enable secret con un algoritmo de cifrado seguro (SHA256 o SHA512).',
                solution: 'enable secret sha256 <password>',
                description: 'Enable secret no está configurado'
            });
        }

        if (!configText.includes('password encryption')) {
            nonCompliant.push({
                severity: 'Media',
                context: 'Sin password encryption',
                recommendation: 'Habilite el comando password encryption para cifrar las contraseñas almacenadas en la configuración.',
                solution: 'service password-encryption',
                description: 'El cifrado de contraseñas no está habilitado'
            });
        } else {
            compliant.push('El cifrado de contraseñas está habilitado');
        }

        // TCP Keepalives (Común en IOS y IOS-XE)
        if (!configText.includes('service tcp-keepalives-in') || !configText.includes('service tcp-keepalives-out')) {
            nonCompliant.push({
                severity: 'Media',
                context: 'tcp keepalives in/out (Estado actual DISABLED)',
                recommendation: 'Habilitar service tcp-keepalives-in y service tcp-keepalives-out.',
                solution: 'service tcp-keepalives-in\nservice tcp-keepalives-out',
                description: 'Los keepalives de TCP (in/out) no están habilitados. Dificulta la detección y cierre de sesiones inactivas.'
            });
        } else {
            compliant.push('Los keepalives de TCP (in/out) están habilitados.');
        }


        // Enabled Services (HTTP, Telnet, etc.) (Común en IOS y IOS-XE)
        if (configText.includes('no ip http server')) {
            compliant.push('Servidor HTTP está deshabilitado');
        } else if (configText.includes('ip http server')) {
            nonCompliant.push({
                severity: 'Baja',
                context: 'ip http server',
                recommendation: 'Deshabilite el servidor HTTP a menos que sea absolutamente necesario.',
                solution: 'no ip http server',
                description: 'El servidor HTTP está habilitado'
            });
        }
        if (configText.includes('line vty 0 4') && configText.includes('transport input telnet')) {
            nonCompliant.push({
                severity: 'Alta',
                context: 'line vty 0 4, transport input telnet',
                recommendation: 'Deshabilite Telnet y utilice SSH para la administración remota.',
                solution: 'no transport input telnet',
                description: 'Telnet está habilitado en las líneas VTY'
            });
        }

        // SSH Configuration (Común en IOS y IOS-XE)
        if (!configText.includes('ip ssh version 2')) {
            nonCompliant.push({
                severity: 'Alta',
                context: 'Sin ip ssh version 2',
                recommendation: 'Habilite la versión 2 de SSH.',
                solution: 'ip ssh version 2',
                description: 'La versión 2 de SSH no está habilitada'
            });
        } else {
            compliant.push('La versión 2 de SSH está habilitada');
        }

        if (!configText.includes('crypto key generate rsa')) {
            nonCompliant.push({
                severity: 'Media',
                context: 'Sin crypto key generate rsa',
                recommendation: 'Genere una clave RSA para SSH.',
                solution: 'crypto key generate rsa',
                description: 'No se ha generado una clave RSA para SSH'
            });
        } else {
             compliant.push('Se ha generado una clave RSA para SSH');
        }

        // VTY and Console Line Configuration (Común en IOS y IOS-XE)
        const vtyLines = configText.split('\n').filter(line => line.trim().startsWith('line vty'));

        for (const vtyLine of vtyLines) {
            const vtyRangeMatch = vtyLine.match(/line vty (\d+) (\d+)/);
            if (vtyRangeMatch) {
                const startVty = parseInt(vtyRangeMatch[1]);
                const endVty = parseInt(vtyRangeMatch[2]);

                const vtyBlockRegex = new RegExp(`line vty ${startVty} ${endVty}([\\s\\S]*?)(?:\\nline vty|\\n!|\\nend|$)`);
                const vtyBlockMatch = configText.match(vtyBlockRegex);

                if (vtyBlockMatch) {
                    const vtyBlock = vtyBlockMatch[1];
                    const loginAuthenticationRemoteMatch = vtyBlock.match(/^\s*login authentication REMOTO/m);
                    const loginLocalMatch = vtyBlock.match(/^\s*login local/m);
                    const passwordMatch = vtyBlock.match(/^\s*password (\S+)/m);


                    if (loginAuthenticationRemoteMatch && radiusConfigured) {
                        compliant.push(`Las líneas VTY ${startVty}-${endVty} utilizan autenticación centralizada (RADIUS).`);
                    } else if (loginLocalMatch) {
                        compliant.push(`Las líneas VTY ${startVty}-${endVty} utilizan autenticación local.`);
                    } else {
                         let description = `Las líneas VTY ${startVty}-${endVty} no tienen una configuración de autenticación segura.`;
                         let recommendation = 'Configure la autenticación para las líneas VTY utilizando login authentication REMOTO (con RADIUS configurado) o login local.';
                         let solution = `line vty ${startVty} ${endVty}\n login authentication REMOTO`;

                         if (!radiusConfigured) {
                             recommendation = 'Configure la autenticación para las líneas VTY utilizando login local o configure RADIUS y use login authentication REMOTO.';
                             solution = `line vty ${startVty} ${endVty}\n login local`;
                             description = `Las líneas VTY ${startVty}-${endVty} no tienen una configuración de autenticación segura y RADIUS no está configurado globalmente.`;
                         }


                         nonCompliant.push({
                            severity: 'Alta',
                            context: vtyLine.trim() + vtyBlock,
                            recommendation: recommendation,
                            solution: solution,
                            description: description
                        });
                    }

                     // Check for privilege 15 within the VTY block
                    if (vtyBlock.includes('privilege level 15')) {
                        nonCompliant.push({
                            severity: 'Alta',
                            context: vtyLine.trim() + vtyBlock.match(/privilege level 15.*/)[0],
                            recommendation: 'Elimine la configuración "privilege level 15" de las líneas VTY. Los usuarios deben iniciar sesión con privilegios mínimos y escalarlos si es necesario.',
                            solution: `No configure "privilege level 15" directamente en las líneas VTY ${startVty}-${endVty}.`,
                            description: `Las líneas VTY ${startVty}-${endVty} tienen configurado el privilegio level 15 directamente`
                        });
                    } else {
                        compliant.push(`Las líneas VTY ${startVty}-${endVty} no tienen configurado el privilegio level 15 directamente`);
                    }
                }
            }
        }


        // User Configuration Analysis (Común en IOS y IOS-XE)
        const userLines = configText.split('\n').filter(line => line.trim().startsWith('username'));

        if (userLines.length > 1) {
            nonCompliant.push({
                severity: 'Media',
                context: userLines.map(line => line.trim()).join('\n'),
                recommendation: 'Considere utilizar un servidor de autenticación centralizado (como AAA con RADIUS/TACACS+) en lugar de múltiples usuarios locales.',
                solution: 'Configure la autenticación centralizada y elimine los usuarios locales innecesarios.',
                description: `Se encontraron múltiples usuarios locales (${userLines.length}). Esto puede dificultar la gestión y auditoría.`
            });
        }

        userLines.forEach(userLine => {
            const usernameMatch = userLine.match(/^username (\S+)/);
            const username = usernameMatch ? usernameMatch[1] : 'Desconocido';

            // Check for privilege 15
            if (userLine.includes('privilege 15')) {
                nonCompliant.push({
                    severity: 'Alta',
                    context: userLine.trim(),
                    recommendation: `Elimine la configuración "privilege 15" para el usuario "${username}". Los usuarios deben iniciar sesión con privilegios mínimos.`,
                    solution: `Elimine "privilege 15" de la línea de configuración del usuario "${username}".`,
                    description: `El usuario "${username}" tiene configurado el privilegio 15 directamente`
                });
            } else {
                compliant.push(`El usuario "${username}" no tiene configurado el privilegio 15 directamente`);
            }

            // Check password encryption type
            if (userLine.includes('secret 5') || userLine.includes('secret 7') || userLine.includes('password')) {
                 nonCompliant.push({
                    severity: 'Alta',
                    context: userLine.trim(),
                    recommendation: `Utilice un algoritmo de cifrado más seguro como SHA256 (tipo 8) o SHA512 (tipo 9) para la contraseña del usuario "${username}".`,
                    solution: `Cambie el tipo de cifrado de la contraseña para el usuario "${username}" a secret 8 o secret 9.`,
                    description: `La contraseña del usuario "${username}" utiliza un cifrado débil (tipo 5, 7 o texto claro)`
                });
            } else if (userLine.includes('secret 8') || userLine.includes('secret 9')) {
                compliant.push(`La contraseña del usuario "${username}" utiliza un cifrado seguro (tipo 8 o 9)`);
            } else {
                 nonCompliant.push({
                    severity: 'Media',
                    context: userLine.trim(),
                    recommendation: `Configure la contraseña del usuario "${username}" utilizando un algoritmo de cifrado seguro (SHA256 o SHA512).`,
                    solution: `Configure la contraseña para el usuario "${username}" con secret 8 o secret 9.`,
                    description: `La contraseña del usuario "${username}" no utiliza un cifrado seguro conocido`
                });
            }
        });

        // RADIUS Configuration Analysis (Común en IOS y IOS-XE)
        const radiusAnalysis = analyzeRadiusConfig(configText);
        compliant.push(...radiusAnalysis.compliant);
        nonCompliant.push(...radiusAnalysis.nonCompliant);

        // NTP Configuration (Común en IOS y IOS-XE)
        const ntpLines = configText.split('\n').filter(line => line.trim().startsWith('ntp server'));
        const ntpServerCount = ntpLines.length;

        if (ntpServerCount < 3) {
            nonCompliant.push({
                severity: 'Media',
                context: ntpLines.length > 0 ? ntpLines.map(line => line.trim()).join('\n') : 'Sin configuración de ntp server',
                recommendation: 'Configure al menos 3 servidores NTP para redundancia y precisión.',
                solution: 'ntp server <IP address 1>\nntp server <IP address 2>\nntp server <IP address 3>',
                description: `Se detectaron ${ntpServerCount} servidores NTP. Se recomiendan al menos 3.`
            });
        } else {
            compliant.push(`Se detectaron ${ntpServerCount} servidores NTP (cumple con la recomendación de mínimo 3).`);
        }

    } else if (osType === 'NX-OS') {
        // Análisis específico para NX-OS
        // Nota: Las configuraciones de NX-OS pueden variar significativamente.
        // Aquí se incluirían análisis específicos para NX-OS.

        // Análisis específico para NX-OS
        // Nota: Las configuraciones de NX-OS pueden variar significativamente.
        // Aquí se incluirían análisis específicos para NX-OS.

        // Análisis de contraseñas en NX-OS
        const nxosUserLines = configText.split('\n').filter(line => line.trim().startsWith('username'));
        nxosUserLines.forEach(userLine => {
             const usernameMatch = userLine.match(/^username (\S+)/);
             const username = usernameMatch ? usernameMatch[1] : 'Desconocido';

             // Verificación de tipo de cifrado en NX-OS (ejemplo: tipo 5 y 7 son débiles)
             if (userLine.includes('password 5') || userLine.includes('password 7')) {
                  nonCompliant.push({
                     severity: 'Alta',
                     context: userLine.trim(),
                     recommendation: `Utilice un algoritmo de cifrado más seguro para la contraseña del usuario "${username}" en NX-OS.`,
                     solution: `Cambie el tipo de cifrado de la contraseña para el usuario "${username}" a un tipo seguro (ej. tipo 8 o 9 si son soportados, o use 'encrypted').`,
                     description: `La contraseña del usuario "${username}" utiliza un cifrado débil en NX-OS (tipo 5 o 7).`
                 });
             } else if (userLine.includes('password 8') || userLine.includes('password 9') || userLine.includes('password encrypted')) {
                 compliant.push(`La contraseña del usuario "${username}" utiliza un cifrado seguro en NX-OS.`);
             } else {
                  nonCompliant.push({
                     severity: 'Media',
                     context: userLine.trim(),
                     recommendation: `Configure la contraseña del usuario "${username}" utilizando un algoritmo de cifrado seguro en NX-OS.`,
                     solution: `Configure la contraseña para el usuario "${username}" con un tipo seguro (ej. tipo 8 o 9 si son soportados, o use 'encrypted').`,
                     description: `La contraseña del usuario "${username}" no utiliza un cifrado seguro conocido en NX-OS.`
                 });
             }

             // Verificación de privilegio 15 en NX-OS (puede ser diferente)
             if (userLine.includes('role network-admin') || userLine.includes('role vdc-admin')) { // Ejemplos de roles de alto privilegio en NX-OS
                 nonCompliant.push({
                     severity: 'Alta',
                     context: userLine.trim(),
                     recommendation: `Revise los roles asignados al usuario "${username}" en NX-OS. Asigne roles con los mínimos privilegios necesarios.`,
                     solution: `Modifique los roles asignados al usuario "${username}" para seguir el principio de mínimo privilegio.`,
                     description: `El usuario "${username}" tiene asignado un rol de alto privilegio en NX-OS.`
                 });
             } else {
                 compliant.push(`El usuario "${username}" no tiene asignado un rol de alto privilegio directo en NX-OS.`);
             }
        });

        // Verificación de SSH en NX-OS
        if (!configText.includes('ssh key rsa 2048')) { // Ejemplo de comando SSH en NX-OS
             nonCompliant.push({
                 severity: 'Media',
                 context: 'Sin ssh key rsa',
                 recommendation: 'Genere una clave RSA de al menos 2048 bits para SSH en NX-OS.',
                 solution: 'ssh key rsa 2048',
                 description: 'No se ha generado una clave RSA para SSH en NX-OS o el tamaño es menor a 2048 bits.'
             });
        } else {
             compliant.push('Se ha generado una clave RSA para SSH en NX-OS de al menos 2048 bits.');
        }

        // Verificación de NTP en NX-OS (puede ser diferente)
        const nxosNtpLines = configText.split('\n').filter(line => line.trim().startsWith('ntp server'));
        const nxosNtpServerCount = nxosNtpLines.length;

        if (nxosNtpServerCount < 3) {
            nonCompliant.push({
                severity: 'Media',
                context: nxosNtpLines.length > 0 ? nxosNtpLines.map(line => line.trim()).join('\n') : 'Sin configuración de ntp server en NX-OS',
                recommendation: 'Configure al menos 3 servidores NTP para redundancia y precisión en NX-OS.',
                solution: 'ntp server <IP address 1>\nntp server <IP address 2>\nntp server <IP address 3>',
                description: `Se detectaron ${nxosNtpServerCount} servidores NTP en NX-OS. Se recomiendan al menos 3.`
            });
        } else {
            compliant.push(`Se detectaron ${nxosNtpServerCount} servidores NTP en NX-OS (cumple con la recomendación de mínimo 3).`);
        }

        // Verificación de Telnet en NX-OS (puede ser diferente)
        if (configText.includes('feature telnet')) {
             nonCompliant.push({
                 severity: 'Alta',
                 context: 'feature telnet',
                 recommendation: 'Deshabilite la característica Telnet en NX-OS y utilice SSH para la administración remota.',
                 solution: 'no feature telnet',
                 description: 'La característica Telnet está habilitada en NX-OS.'
             });
        } else {
             compliant.push('La característica Telnet está deshabilitada en NX-OS.');
        }

        // Verificación de HTTP/HTTPS en NX-OS (puede ser diferente)
        if (configText.includes('feature http-server')) {
             nonCompliant.push({
                 severity: 'Baja',
                 context: 'feature http-server',
                 recommendation: 'Deshabilite la característica HTTP Server en NX-OS a menos que sea absolutamente necesario.',
                 solution: 'no feature http-server',
                 description: 'La característica HTTP Server está habilitada en NX-OS.'
             });
        } else {
             compliant.push('La característica HTTP Server está deshabilitada en NX-OS.');
        }

        // Añadir más análisis específicos para NX-OS según sea necesario
    }


    let riskScore = 0;
    nonCompliant.forEach(item => {
        if (item.severity === 'Alta') {
            riskScore += 10;
        } else if (item.severity === 'Media') {
            riskScore += 5;
        } else if (item.severity === 'Baja') {
            riskScore += 1;
        }
    });

    const severityCounts = {
        Alta: 0,
        Media: 0,
        Baja: 0
    };

    nonCompliant.forEach(item => {
        if (severityCounts.hasOwnProperty(item.severity)) {
            severityCounts[item.severity]++;
        }
    });

    // Extract OS Version
    let osVersion = 'No detectada';
    const iosMatch = configText.match(/Cisco IOS Software.*?, Version ([\d\.\(E\)\w]+)/);
    const iosxeMatch = configText.match(/Cisco IOS-XE Software.*?, Version ([\d\.\(E\)\w]+)/);
    const nxosMatch = configText.match(/Cisco NX-OS Software.*?, Version ([\d\.\(E\)\w]+)/);

    if (iosMatch) {
        osVersion = `IOS ${iosMatch[1]}`;
    } else if (iosxeMatch) {
        osVersion = `IOS-XE ${iosxeMatch[1]}`;
    } else if (nxosMatch) {
        osVersion = `NX-OS ${nxosMatch[1]}`;
    }

    console.log("OS Type detected:", osType);
    console.log("OS Version extracted:", osVersion);

    return { compliant, nonCompliant, riskScore, severityCounts, configText, osType, osVersion }; // Return osType and osVersion
}

function displayResults(results) {
    const compliantList = document.getElementById('compliant').querySelector('ul');
    const nonCompliantList = document.getElementById('nonCompliant').querySelector('ul');
    const analysisDate = new Date().toLocaleDateString();
    const osVersion = results.osVersion; // Use extracted OS version
    const compliantCount = results.compliant.length;
    const nonCompliantCount = results.nonCompliant.length;
    const riskScore = results.riskScore;
    const osType = results.osType; // Use extracted OS type

    document.getElementById('analysis-date').textContent = analysisDate;
    document.getElementById('ios-version').textContent = osVersion; // Update ID to reflect OS version
    document.getElementById('compliant-count').textContent = compliantCount;
    document.getElementById('non-compliant-count').textContent = nonCompliantCount;
    document.getElementById('risk-score').textContent = riskScore;
    document.getElementById('os-type').textContent = osType; // Display OS Type


    compliantList.innerHTML = '';
    nonCompliantList.innerHTML = '';

    results.compliant.forEach(item => {
        const li = document.createElement('li');
        li.textContent = item;
        compliantList.appendChild(li);
    });

    results.nonCompliant.forEach(item => {
        const li = document.createElement('li');
        li.classList.add(`severity-${item.severity.toLowerCase()}`);
        li.innerHTML = `
            <strong>${item.description}</strong>
            <p><strong>Gravedad:</strong> ${item.severity}</p>
            <p><strong>Contexto:</strong> <code>${item.context}</code></p>
            <p><strong>Recomendación:</strong> ${item.recommendation}</p>
            <p><strong>Mitigar:</strong> <code>${item.solution}</code></p>
        `;
        nonCompliantList.appendChild(li);
    });

    // Enable the export button
    document.getElementById('export-report-btn').disabled = false;

    // Render severity chart
    const severityCounts = results.severityCounts;
    const ctx = document.getElementById('severityChart').getContext('2d');

    // Destroy existing chart if it exists
    if (window.severityChartInstance) {
        window.severityChartInstance.destroy();
    }

    window.severityChartInstance = new Chart(ctx, { // Store chart instance
        type: 'bar',
        data: {
            labels: ['Alta', 'Media', 'Baja'],
            datasets: [{
                label: 'Cantidad de Hallazgos por Gravedad',
                data: [severityCounts.Alta, severityCounts.Media, severityCounts.Baja],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.5)', // Red for Alta
                    'rgba(255, 159, 64, 0.5)', // Orange for Media
                    'rgba(75, 192, 192, 0.5)'  // Green for Baja
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(255, 159, 64, 1)',
                    'rgba(75, 192, 192, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Cantidad de Hallazgos'
                    }
                },
                x: {
                     title: {
                        display: true,
                        text: 'Gravedad'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Resumen de Hallazgos por Gravedad'
                }
            }
        }
    });
}


async function exportReport() {
    console.log("exportReport function called");
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    let yOffset = 10; // Vertical offset for adding content

    const addText = (text, x, y, options = {}) => {
        doc.text(text, x, y, options);
        yOffset = y + 7; // Update offset for next content
    };

    const addTitle = (text) => {
        doc.setFontSize(18);
        doc.text(text, 10, yOffset);
        yOffset += 10;
        doc.setFontSize(12); // Reset font size
    };

    const addSectionTitle = (text) => {
        doc.setFontSize(14);
        doc.text(text, 10, yOffset);
        yOffset += 8;
        doc.setFontSize(12); // Reset font size
    };

    const addParagraph = (text) => {
        const lines = doc.splitTextToSize(text, 180); // Wrap text
        doc.text(lines, 10, yOffset);
        yOffset += (lines.length * 5) + 5;
    };

    const addList = (items) => {
        items.forEach(item => {
            const lines = doc.splitTextToSize(`- ${item}`, 180);
            doc.text(lines, 15, yOffset);
            yOffset += (lines.length * 5);
        });
        yOffset += 5;
    };

    const addKeyValuePair = (key, value) => {
        addParagraph(`<strong>${key}:</strong> ${value}`);
    };

    const addFinding = (finding) => {
        doc.setFontSize(12);
        addParagraph(`<strong>Descripción:</strong> ${finding.description}`);
        addParagraph(`<strong>Gravedad:</strong> ${finding.severity}`);
        addParagraph(`<strong>Contexto:</strong> <code>${finding.context}</code>`);
        addParagraph(`<strong>Recomendación:</strong> ${finding.recommendation}`);
        addParagraph(`<strong>Mitigar:</strong> <code>${finding.solution}</code>`);
        yOffset += 5; // Add space between findings
    };

    const addChart = async (chartId, title) => {
        addSectionTitle(title);
        const canvas = document.getElementById(chartId);
        if (canvas) {
            const imgData = await html2canvas(canvas).then(canvas => canvas.toDataURL('image/png'));
            const imgWidth = 180; // Adjust as needed
            const imgHeight = canvas.height * imgWidth / canvas.width;
            doc.addImage(imgData, 'PNG', 10, yOffset, imgWidth, imgHeight);
            yOffset += imgHeight + 10;
        } else {
            addParagraph(`No se pudo generar el gráfico: ${title}`);
        }
    };

    const addTemporaryChart = async (chartConfig, title) => {
        addSectionTitle(title);
        const tempCanvas = document.createElement('canvas');
        tempCanvas.width = 600; // Match display chart size
        tempCanvas.height = 300; // Match display chart size
        const tempCtx = tempCanvas.getContext('2d');

        new Chart(tempCtx, chartConfig);

        const imgData = await html2canvas(tempCanvas).then(canvas => canvas.toDataURL('image/png'));
        const imgWidth = 180; // Adjust as needed
        const imgHeight = tempCanvas.height * imgWidth / tempCanvas.width;
        doc.addImage(imgData, 'PNG', 10, yOffset, imgWidth, imgHeight);
        yOffset += imgHeight + 10;

        // Clean up the temporary canvas
        tempCanvas.remove();
    };


    const results = window.lastAnalysisResults;
    if (!results) {
        alert("No hay resultados de análisis para exportar. Por favor, analiza una configuración primero.");
        console.error("No analysis results available for export.");
        console.log("No analysis results available for export."); // Added console log
        return;
    }
    console.log("Analysis results found:", results);

    // --- Portada ---
    addTitle("Informe de Análisis de Configuración Cisco");
    addText("Generado por: CybersecurityJP - Analizador de Vulnerabilidades en Configuraciones Cisco", 10, yOffset);
    addText(`Fecha del Análisis: ${new Date().toLocaleDateString()}`, 10, yOffset);
    yOffset += 20; // Add some space after cover

    // --- Índice (Placeholder) ---
    doc.addPage();
    yOffset = 10;
    addTitle("Índice");
    addParagraph("Este índice se generará dinámicamente."); // Placeholder for now

    // --- Introducción ---
    doc.addPage();
    yOffset = 10;
    addSectionTitle("1. Introducción");
    addParagraph("Este informe presenta los resultados del análisis de seguridad realizado sobre el archivo de configuración de un dispositivo Cisco. El análisis se centra en identificar posibles vulnerabilidades y desviaciones de las buenas prácticas de seguridad recomendadas.");

    // --- Resumen Ejecutivo ---
    doc.addPage();
    yOffset = 10;
    addSectionTitle("2. Resumen Ejecutivo");
    addParagraph(`El análisis identificó ${results.nonCompliant.length} hallazgos de seguridad y ${results.compliant.length} puntos de cumplimiento en la configuración del dispositivo. La puntuación de riesgo calculada es de ${results.riskScore}.`);
    // Add more summary details if needed

    // --- Datos del Dispositivo Analizado ---
    doc.addPage();
    yOffset = 10;
    addSectionTitle("3. Datos del Dispositivo Analizado");
    addKeyValuePair("Nombre del Archivo de Configuración", document.getElementById('file-name').textContent.replace('Archivo seleccionado: ', ''));
    addKeyValuePair("Fecha del Análisis", document.getElementById('analysis-date').textContent);
    addKeyValuePair("Sistema Operativo Detectado", document.getElementById('os-type').textContent); // Display OS Type
    addKeyValuePair("Versión del Sistema Operativo", document.getElementById('ios-version').textContent); // Display OS Version
    // Add more device data if available from configText

    // --- Puntos de Cumplimiento ---
    doc.addPage();
    yOffset = 10;
    addSectionTitle("4. Puntos de Cumplimiento");
    if (results.compliant.length > 0) {
        addList(results.compliant);
    } else {
        addParagraph("No se identificaron puntos de cumplimiento específicos en este análisis.");
    }


    // --- Hallazgos ---
    doc.addPage();
    yOffset = 10;
    addSectionTitle("5. Hallazgos");
    if (results.nonCompliant.length > 0) {
        results.nonCompliant.forEach(finding => {
            addFinding(finding);
        });
    } else {
        addParagraph("No se identificaron hallazgos de seguridad en este análisis.");
    }


    // --- Gráficos ---
    doc.addPage();
    yOffset = 10;
    addSectionTitle("6. Gráficos del Análisis");
    addParagraph("Los siguientes gráficos resumen los resultados del análisis:");

    // Gráfico de Nivel de Cumplimiento
    const compliantChartConfig = {
        type: 'pie',
        data: {
            labels: ['Cumplimientos', 'Hallazgos'],
            datasets: [{
                data: [results.compliant.length, results.nonCompliant.length],
                backgroundColor: [
                    'rgba(75, 192, 192, 0.5)', // Green for Compliant
                    'rgba(255, 99, 132, 0.5)'  // Red for Non-Compliant
                ],
                borderColor: [
                    'rgba(75, 192, 192, 1)',
                    'rgba(255, 99, 132, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: false, // Important for html2canvas
            maintainAspectRatio: false, // Important for html2canvas
            plugins: {
                title: {
                    display: true,
                    text: 'Nivel de Cumplimiento'
                }
            }
        }
    };
    await addTemporaryChart(compliantChartConfig, "Gráfico de Nivel de Cumplimiento");


    // Gráfico de Nivel de Riesgo (Simple Bar or Gauge - Bar is easier with Chart.js)
    const riskChartConfig = {
         type: 'bar',
         data: {
             labels: ['Puntuación de Riesgo'],
             datasets: [{
                 label: 'Puntuación',
                 data: [results.riskScore],
                 backgroundColor: results.riskScore > 50 ? 'rgba(255, 99, 132, 0.5)' : (results.riskScore > 20 ? 'rgba(255, 159, 64, 0.5)' : 'rgba(75, 192, 192, 0.5)'),
                 borderColor: results.riskScore > 50 ? 'rgba(255, 99, 132, 1)' : (results.riskScore > 20 ? 'rgba(255, 159, 64, 1)' : 'rgba(75, 192, 192, 1)'),
                 borderWidth: 1
             }]
         },
         options: {
             responsive: false, // Important for html2canvas
             maintainAspectRatio: false, // Important for html2canvas
             scales: {
                 y: {
                     beginAtZero: true,
                     max: 100, // Assuming a max risk score of 100 for visualization
                     title: {
                         display: true,
                         text: 'Puntuación de Riesgo'
                     }
                 }
             },
             plugins: {
                 legend: {
                     display: false
                 },
                 title: {
                     display: true,
                     text: 'Nivel de Riesgo'
                 }
             }
         }
     };
     await addTemporaryChart(riskChartConfig, "Gráfico de Nivel de Riesgo");


    // Gráfico Resumen de Vulnerabilidades (Severity Chart)
    await addChart('severityChart', "Gráfico Resumen de Vulnerabilidades por Gravedad");


    // --- Conclusión ---
    doc.addPage();
    yOffset = 10;
    addSectionTitle("7. Conclusión");
    addParagraph("Este informe proporciona una visión general de la postura de seguridad del dispositivo analizado. Se recomienda revisar los hallazgos y aplicar las soluciones propuestas para mejorar la seguridad.");


    // Save the PDF
    doc.save("informe_analisis_cisco.pdf");
}


function analyzeRadiusConfig(configText) {
    const compliant = [];
    const nonCompliant = [];

    // Analyze aaa authentication login REMOTO group radius local enable
    if (configText.includes('aaa authentication login REMOTO group radius local enable')) {
        compliant.push('Configuración AAA authentication login REMOTO group radius local enable encontrada (cumple con la buena práctica de usar RADIUS con fallback local).');
    } else {
        nonCompliant.push({
            severity: 'Alta',
            context: 'Sin aaa authentication login REMOTO group radius local enable',
            recommendation: 'Configure AAA authentication login para usar RADIUS con un método de fallback local.',
            solution: 'aaa authentication login REMOTO group radius local enable',
            description: 'La configuración AAA authentication login REMOTO group radius local enable no está presente.'
        });
    }

    // Analyze ip radius source-interface
    const radiusSourceInterfaceMatch = configText.match(/^ip radius source-interface (\S+)/m);
    if (radiusSourceInterfaceMatch) {
        compliant.push(`Configuración ip radius source-interface ${radiusSourceInterfaceMatch[1]} encontrada (cumple con la buena práctica de especificar la interfaz de origen).`);
    } else {
        nonCompliant.push({
            severity: 'Media',
            context: 'Sin ip radius source-interface',
            recommendation: 'Configure una interfaz de origen para los paquetes RADIUS.',
            solution: 'ip radius source-interface <interface>',
            description: 'La configuración ip radius source-interface no está presente.'
        });
    }

    // Analyze radius server configurations
    const servicePasswordEncryptionEnabled = configText.includes('service password-encryption');
    const radiusServerBlocks = configText.split(/(?=^radius server)/m).filter(block => block.trim().startsWith('radius server'));

    if (radiusServerBlocks.length > 0) {
        compliant.push(`Se encontraron ${radiusServerBlocks.length} configuraciones de servidor RADIUS.`);
        radiusServerBlocks.forEach(block => {
            const serverNameMatch = block.match(/^radius server (\S+)/m);
            const serverName = serverNameMatch ? serverNameMatch[1] : 'Desconocido';
            const keyMatch = block.match(/^\s*key (\S+)/m); // Look for 'key' line within the block, allowing for indentation

            // Extract only the relevant lines for context
            const relevantContextLines = block.split('\n').filter(line =>
                line.trim().startsWith('radius server') || line.trim().startsWith('address') || line.trim().startsWith('key')
            ).join('\n');


            if (keyMatch) {
                const key = keyMatch[1];
                // Heuristic to check if the key is likely in clear text
                const isLikelyClearText = /^[a-zA-Z0-9_]+$/.test(key);

                if (isLikelyClearText && servicePasswordEncryptionEnabled) {
                     nonCompliant.push({
                        severity: 'Alta',
                        context: relevantContextLines.trim(),
                        recommendation: `La clave compartida para el servidor RADIUS "${serverName}" parece estar en texto claro a pesar de tener service password-encryption habilitado. Verifique la configuración y asegúrese de que la clave esté cifrada.`,
                        solution: `Reconfigure la clave compartida para el servidor RADIUS "${serverName}" para asegurar que esté cifrada.`,
                        description: `La clave compartida para el servidor RADIUS "${serverName}" parece estar en texto claro.`
                    });
                } else if (!servicePasswordEncryptionEnabled) {
                     nonCompliant.push({
                        severity: 'Alta',
                        context: relevantContextLines.trim(),
                        recommendation: 'Habilite service password-encryption para cifrar las claves compartidas de RADIUS y otras contraseñas en la configuración.',
                        solution: `service password-encryption\n${relevantContextLines.trim()}`,
                        description: `La clave compartida para el servidor RADIUS "${serverName}" no está cifrada porque service password-encryption no está habilitado.`
                    });
                }
                 else {
                    compliant.push(`La configuración del servidor RADIUS "${serverName}" tiene una clave compartida configurada y parece estar cifrada.`);
                }
            } else {
                 nonCompliant.push({
                    severity: 'Alta',
                    context: relevantContextLines.trim(),
                    recommendation: `Configure una clave compartida (key) para el servidor RADIUS "${serverName}".`,
                    solution: `${relevantContextLines.trim()}\n key <shared-secret>`,
                    description: `La configuración del servidor RADIUS "${serverName}" no tiene una clave compartida configurada.`
                });
            }
        });
    } else {
        nonCompliant.push({
            severity: 'Alta',
            context: 'Sin configuración de servidor RADIUS',
            recommendation: 'Configure al menos un servidor RADIUS.',
            solution: 'radius server <name>\n address ipv4 <ip_address>\n key <shared-secret>',
            description: 'No se encontraron configuraciones de servidor RADIUS.'
        });
    }

    return { compliant, nonCompliant };
}

function displayResults(results) {
    const compliantList = document.getElementById('compliant').querySelector('ul');
    const nonCompliantList = document.getElementById('nonCompliant').querySelector('ul');
    const analysisDate = new Date().toLocaleDateString();
    const iosVersion = results.iosVersion; // Use extracted IOS version
    const compliantCount = results.compliant.length;
    const nonCompliantCount = results.nonCompliant.length;
    const riskScore = results.riskScore;

    document.getElementById('analysis-date').textContent = analysisDate;
    document.getElementById('ios-version').textContent = iosVersion;
    document.getElementById('compliant-count').textContent = compliantCount;
    document.getElementById('non-compliant-count').textContent = nonCompliantCount;
    document.getElementById('risk-score').textContent = riskScore;

    compliantList.innerHTML = '';
    nonCompliantList.innerHTML = '';

    results.compliant.forEach(item => {
        const li = document.createElement('li');
        li.textContent = item;
        compliantList.appendChild(li);
    });

    results.nonCompliant.forEach(item => {
        const li = document.createElement('li');
        li.classList.add(`severity-${item.severity.toLowerCase()}`);
        li.innerHTML = `
            <strong>${item.description}</strong>
            <p><strong>Gravedad:</strong> ${item.severity}</p>
            <p><strong>Contexto:</strong> <code>${item.context}</code></p>
            <p><strong>Recomendación:</strong> ${item.recommendation}</p>
            <p><strong>Mitigar:</strong> <code>${item.solution}</code></p>
        `;
        nonCompliantList.appendChild(li);
    });

    // Enable the export button
    document.getElementById('export-report-btn').disabled = false;

    // Render severity chart
    const severityCounts = results.severityCounts;
    const ctx = document.getElementById('severityChart').getContext('2d');

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Alta', 'Media', 'Baja'],
            datasets: [{
                label: 'Cantidad de Hallazgos por Gravedad',
                data: [severityCounts.Alta, severityCounts.Media, severityCounts.Baja],
                backgroundColor: [
                    'rgba(255, 99, 132, 0.5)', // Red for Alta
                    'rgba(255, 159, 64, 0.5)', // Orange for Media
                    'rgba(75, 192, 192, 0.5)'  // Green for Baja
                ],
                borderColor: [
                    'rgba(255, 99, 132, 1)',
                    'rgba(255, 159, 64, 1)',
                    'rgba(75, 192, 192, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Cantidad de Hallazgos'
                    }
                },
                x: {
                     title: {
                        display: true,
                        text: 'Gravedad'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Resumen de Hallazgos por Gravedad'
                }
            }
        }
    });
}


async function exportReport() {
    console.log("exportReport function called");
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    let yOffset = 10; // Vertical offset for adding content

    const addText = (text, x, y, options = {}) => {
        doc.text(text, x, y, options);
        yOffset = y + 7; // Update offset for next content
    };

    const addTitle = (text) => {
        doc.setFontSize(18);
        doc.text(text, 10, yOffset);
        yOffset += 10;
        doc.setFontSize(12); // Reset font size
    };

    const addSectionTitle = (text) => {
        doc.setFontSize(14);
        doc.text(text, 10, yOffset);
        yOffset += 8;
        doc.setFontSize(12); // Reset font size
    };

    const addParagraph = (text) => {
        const lines = doc.splitTextToSize(text, 180); // Wrap text
        doc.text(lines, 10, yOffset);
        yOffset += (lines.length * 5) + 5;
    };

    const addList = (items) => {
        items.forEach(item => {
            const lines = doc.splitTextToSize(`- ${item}`, 180);
            doc.text(lines, 15, yOffset);
            yOffset += (lines.length * 5);
        });
        yOffset += 5;
    };

    const addKeyValuePair = (key, value) => {
        addParagraph(`<strong>${key}:</strong> ${value}`);
    };

    const addFinding = (finding) => {
        doc.setFontSize(12);
        addParagraph(`<strong>Descripción:</strong> ${finding.description}`);
        addParagraph(`<strong>Gravedad:</strong> ${finding.severity}`);
        addParagraph(`<strong>Contexto:</strong> <code>${finding.context}</code>`);
        addParagraph(`<strong>Recomendación:</strong> ${finding.recommendation}`);
        addParagraph(`<strong>Mitigar:</strong> <code>${finding.solution}</code>`);
        yOffset += 5; // Add space between findings
    };

    const addChart = async (chartId, title) => {
        addSectionTitle(title);
        const canvas = document.getElementById(chartId);
        if (canvas) {
            const imgData = await html2canvas(canvas).then(canvas => canvas.toDataURL('image/png'));
            const imgWidth = 180; // Adjust as needed
            const imgHeight = canvas.height * imgWidth / canvas.width;
            doc.addImage(imgData, 'PNG', 10, yOffset, imgWidth, imgHeight);
            yOffset += imgHeight + 10;
        } else {
            addParagraph(`No se pudo generar el gráfico: ${title}`);
        }
    };

    const addTemporaryChart = async (chartConfig, title) => {
        addSectionTitle(title);
        const tempCanvas = document.createElement('canvas');
        tempCanvas.width = 600; // Match display chart size
        tempCanvas.height = 300; // Match display chart size
        const tempCtx = tempCanvas.getContext('2d');

        new Chart(tempCtx, chartConfig);

        const imgData = await html2canvas(tempCanvas).then(canvas => canvas.toDataURL('image/png'));
        const imgWidth = 180; // Adjust as needed
        const imgHeight = tempCanvas.height * imgWidth / tempCanvas.width;
        doc.addImage(imgData, 'PNG', 10, yOffset, imgWidth, imgHeight);
        yOffset += imgHeight + 10;

        // Clean up the temporary canvas
        tempCanvas.remove();
    };


    const results = window.lastAnalysisResults;
    if (!results) {
        alert("No hay resultados de análisis para exportar. Por favor, analiza una configuración primero.");
        console.error("No analysis results available for export.");
        console.log("No analysis results available for export."); // Added console log
        return;
    }
    console.log("Analysis results found:", results);

    // --- Portada ---
    addTitle("Informe de Análisis de Configuración Cisco");
    addText("Generado por: CybersecurityJP - Analizador de Vulnerabilidades en Configuraciones Cisco", 10, yOffset);
    addText(`Fecha del Análisis: ${new Date().toLocaleDateString()}`, 10, yOffset);
    yOffset += 20; // Add some space after cover

    // --- Índice (Placeholder) ---
    doc.addPage();
    yOffset = 10;
    addTitle("Índice");
    addParagraph("Este índice se generará dinámicamente."); // Placeholder for now

    // --- Introducción ---
    doc.addPage();
    yOffset = 10;
    addSectionTitle("1. Introducción");
    addParagraph("Este informe presenta los resultados del análisis de seguridad realizado sobre el archivo de configuración de un dispositivo Cisco. El análisis se centra en identificar posibles vulnerabilidades y desviaciones de las buenas prácticas de seguridad recomendadas.");

    // --- Resumen Ejecutivo ---
    doc.addPage();
    yOffset = 10;
    addSectionTitle("2. Resumen Ejecutivo");
    addParagraph(`El análisis identificó ${results.nonCompliant.length} hallazgos de seguridad y ${results.compliant.length} puntos de cumplimiento en la configuración del dispositivo. La puntuación de riesgo calculada es de ${results.riskScore}.`);
    // Add more summary details if needed

    // --- Datos del Dispositivo Analizado ---
    doc.addPage();
    yOffset = 10;
    addSectionTitle("3. Datos del Dispositivo Analizado");
    addKeyValuePair("Nombre del Archivo de Configuración", document.getElementById('file-name').textContent.replace('Archivo seleccionado: ', ''));
    addKeyValuePair("Fecha del Análisis", document.getElementById('analysis-date').textContent);
    addKeyValuePair("Versión IOS Detectada (Estimada)", document.getElementById('ios-version').textContent); // Placeholder
    // Add more device data if available from configText

    // --- Puntos de Cumplimiento ---
    doc.addPage();
    yOffset = 10;
    addSectionTitle("4. Puntos de Cumplimiento");
    if (results.compliant.length > 0) {
        addList(results.compliant);
    } else {
        addParagraph("No se identificaron puntos de cumplimiento específicos en este análisis.");
    }


    // --- Hallazgos ---
    doc.addPage();
    yOffset = 10;
    addSectionTitle("5. Hallazgos");
    if (results.nonCompliant.length > 0) {
        results.nonCompliant.forEach(finding => {
            addFinding(finding);
        });
    } else {
        addParagraph("No se identificaron hallazgos de seguridad en este análisis.");
    }


    // --- Gráficos ---
    doc.addPage();
    yOffset = 10;
    addSectionTitle("6. Gráficos del Análisis");
    addParagraph("Los siguientes gráficos resumen los resultados del análisis:");

    // Gráfico de Nivel de Cumplimiento
    const compliantChartConfig = {
        type: 'pie',
        data: {
            labels: ['Cumplimientos', 'Hallazgos'],
            datasets: [{
                data: [results.compliant.length, results.nonCompliant.length],
                backgroundColor: [
                    'rgba(75, 192, 192, 0.5)', // Green for Compliant
                    'rgba(255, 99, 132, 0.5)'  // Red for Non-Compliant
                ],
                borderColor: [
                    'rgba(75, 192, 192, 1)',
                    'rgba(255, 99, 132, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: false, // Important for html2canvas
            maintainAspectRatio: false, // Important for html2canvas
            plugins: {
                title: {
                    display: true,
                    text: 'Nivel de Cumplimiento'
                }
            }
        }
    };
    await addTemporaryChart(compliantChartConfig, "Gráfico de Nivel de Cumplimiento");


    // Gráfico de Nivel de Riesgo (Simple Bar or Gauge - Bar is easier with Chart.js)
    const riskChartConfig = {
         type: 'bar',
         data: {
             labels: ['Puntuación de Riesgo'],
             datasets: [{
                 label: 'Puntuación',
                 data: [results.riskScore],
                 backgroundColor: results.riskScore > 50 ? 'rgba(255, 99, 132, 0.5)' : (results.riskScore > 20 ? 'rgba(255, 159, 64, 0.5)' : 'rgba(75, 192, 192, 0.5)'),
                 borderColor: results.riskScore > 50 ? 'rgba(255, 99, 132, 1)' : (results.riskScore > 20 ? 'rgba(255, 159, 64, 1)' : 'rgba(75, 192, 192, 1)'),
                 borderWidth: 1
             }]
         },
         options: {
             responsive: false, // Important for html2canvas
             maintainAspectRatio: false, // Important for html2canvas
             scales: {
                 y: {
                     beginAtZero: true,
                     max: 100, // Assuming a max risk score of 100 for visualization
                     title: {
                         display: true,
                         text: 'Puntuación de Riesgo'
                     }
                 }
             },
             plugins: {
                 legend: {
                     display: false
                 },
                 title: {
                     display: true,
                     text: 'Nivel de Riesgo'
                 }
             }
         }
     };
     await addTemporaryChart(riskChartConfig, "Gráfico de Nivel de Riesgo");


    // Gráfico Resumen de Vulnerabilidades (Severity Chart)
    await addChart('severityChart', "Gráfico Resumen de Vulnerabilidades por Gravedad");


    // --- Conclusión ---
    doc.addPage();
    yOffset = 10;
    addSectionTitle("7. Conclusión");
    addParagraph("Este informe proporciona una visión general de la postura de seguridad del dispositivo analizado. Se recomienda revisar los hallazgos y aplicar las soluciones propuestas para mejorar la seguridad.");


    // Save the PDF
    doc.save("informe_analisis_cisco.pdf");
}


function analyzeRadiusConfig(configText) {
    const compliant = [];
    const nonCompliant = [];

    // Analyze aaa authentication login REMOTO group radius local enable
    if (configText.includes('aaa authentication login REMOTO group radius local enable')) {
        compliant.push('Configuración AAA authentication login REMOTO group radius local enable encontrada (cumple con la buena práctica de usar RADIUS con fallback local).');
    } else {
        nonCompliant.push({
            severity: 'Alta',
            context: 'Sin aaa authentication login REMOTO group radius local enable',
            recommendation: 'Configure AAA authentication login para usar RADIUS con un método de fallback local.',
            solution: 'aaa authentication login REMOTO group radius local enable',
            description: 'La configuración AAA authentication login REMOTO group radius local enable no está presente.'
        });
    }

    // Analyze ip radius source-interface
    const radiusSourceInterfaceMatch = configText.match(/^ip radius source-interface (\S+)/m);
    if (radiusSourceInterfaceMatch) {
        compliant.push(`Configuración ip radius source-interface ${radiusSourceInterfaceMatch[1]} encontrada (cumple con la buena práctica de especificar la interfaz de origen).`);
    } else {
        nonCompliant.push({
            severity: 'Media',
            context: 'Sin ip radius source-interface',
            recommendation: 'Configure una interfaz de origen para los paquetes RADIUS.',
            solution: 'ip radius source-interface <interface>',
            description: 'La configuración ip radius source-interface no está presente.'
        });
    }

    // Analyze radius server configurations
    const servicePasswordEncryptionEnabled = configText.includes('service password-encryption');
    const radiusServerBlocks = configText.split(/(?=^radius server)/m).filter(block => block.trim().startsWith('radius server'));

    if (radiusServerBlocks.length > 0) {
        compliant.push(`Se encontraron ${radiusServerBlocks.length} configuraciones de servidor RADIUS.`);
        radiusServerBlocks.forEach(block => {
            const serverNameMatch = block.match(/^radius server (\S+)/m);
            const serverName = serverNameMatch ? serverNameMatch[1] : 'Desconocido';
            const keyMatch = block.match(/^\s*key (\S+)/m); // Look for 'key' line within the block, allowing for indentation

            // Extract only the relevant lines for context
            const relevantContextLines = block.split('\n').filter(line =>
                line.trim().startsWith('radius server') || line.trim().startsWith('address') || line.trim().startsWith('key')
            ).join('\n');


            if (keyMatch) {
                const key = keyMatch[1];
                // Heuristic to check if the key is likely in clear text
                const isLikelyClearText = /^[a-zA-Z0-9_]+$/.test(key);

                if (isLikelyClearText && servicePasswordEncryptionEnabled) {
                     nonCompliant.push({
                        severity: 'Alta',
                        context: relevantContextLines.trim(),
                        recommendation: `La clave compartida para el servidor RADIUS "${serverName}" parece estar en texto claro a pesar de tener service password-encryption habilitado. Verifique la configuración y asegúrese de que la clave esté cifrada.`,
                        solution: `Reconfigure la clave compartida para el servidor RADIUS "${serverName}" para asegurar que esté cifrada.`,
                        description: `La clave compartida para el servidor RADIUS "${serverName}" parece estar en texto claro.`
                    });
                } else if (!servicePasswordEncryptionEnabled) {
                     nonCompliant.push({
                        severity: 'Alta',
                        context: relevantContextLines.trim(),
                        recommendation: 'Habilite service password-encryption para cifrar las claves compartidas de RADIUS y otras contraseñas en la configuración.',
                        solution: `service password-encryption\n${relevantContextLines.trim()}`,
                        description: `La clave compartida para el servidor RADIUS "${serverName}" no está cifrada porque service password-encryption no está habilitado.`
                    });
                }
                 else {
                    compliant.push(`La configuración del servidor RADIUS "${serverName}" tiene una clave compartida configurada y parece estar cifrada.`);
                }
            } else {
                 nonCompliant.push({
                    severity: 'Alta',
                    context: relevantContextLines.trim(),
                    recommendation: `Configure una clave compartida (key) para el servidor RADIUS "${serverName}".`,
                    solution: `${relevantContextLines.trim()}\n key <shared-secret>`,
                    description: `La configuración del servidor RADIUS "${serverName}" no tiene una clave compartida configurada.`
                });
            }
        });
    } else {
        nonCompliant.push({
            severity: 'Alta',
            context: 'Sin configuración de servidor RADIUS',
            recommendation: 'Configure al menos un servidor RADIUS.',
            solution: 'radius server <name>\n address ipv4 <ip_address>\n key <shared-secret>',
            description: 'No se encontraron configuraciones de servidor RADIUS.'
        });
    }

    return { compliant, nonCompliant };
}
