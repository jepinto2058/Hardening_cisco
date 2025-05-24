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
            window.lastAnalysisResults = analysisResults; // Store results globally for export
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
    // Add event listeners for new export buttons
    document.getElementById('export-json-btn').addEventListener('click', exportJSON);
    document.getElementById('export-csv-btn').addEventListener('click', exportCSV);
});


function analyzeCiscoConfig(configText) {
    let compliant = [];
    let nonCompliant = [];

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

    const vlanAnalysis = analyzeVlanSecurity(configText);
    compliant.push(...vlanAnalysis.compliant);
    nonCompliant.push(...vlanAnalysis.nonCompliant);

    // Call the new function and merge results
    const unusedInterfacesAnalysis = analyzeUnusedInterfaces(configText);
    compliant = compliant.concat(unusedInterfacesAnalysis.compliant);
    nonCompliant = nonCompliant.concat(unusedInterfacesAnalysis.nonCompliant);


    return { compliant, nonCompliant, riskScore, severityCounts, configText, osType, osVersion }; // Return osType and osVersion
}

function analyzeVlanSecurity(configText) {
    const compliant = [];
    const nonCompliant = [];

    // Regex para encontrar configuraciones de interfaz que asignan VLANs
    // Busca líneas que empiecen con 'interface', seguidas de cualquier caracter,
    // y luego líneas que contengan 'switchport access vlan' o 'switchport trunk native vlan'
    const interfaceBlocks = configText.split(/(?=^interface)/m).filter(block => block.trim().startsWith('interface'));

    interfaceBlocks.forEach(block => {
        const interfaceMatch = block.match(/^interface (\S+)/m);
        if (interfaceMatch) {
            const interfaceName = interfaceMatch[1];

            // Verificar si la VLAN 1 está configurada como VLAN de acceso
            const accessVlanMatch = block.match(/^\s*switchport access vlan (\d+)/m);
            if (accessVlanMatch && parseInt(accessVlanMatch[1]) === 1) {
                nonCompliant.push({
                    severity: 'Alta',
                    context: block.trim().split('\n').filter(line => line.trim().startsWith('interface') || line.trim().includes('switchport access vlan')).join('\n'),
                    recommendation: `Cambie la VLAN de acceso para la interfaz ${interfaceName} a una VLAN diferente a la por defecto (VLAN 1).`,
                    solution: `interface ${interfaceName}\n switchport access vlan <nueva_vlan>`,
                    description: `La interfaz ${interfaceName} está configurada con la VLAN de acceso por defecto (VLAN 1).`
                });
            }

            // Verificar si la VLAN 1 está configurada como VLAN nativa en un trunk
            const nativeVlanMatch = block.match(/^\s*switchport trunk native vlan (\d+)/m);
            if (nativeVlanMatch && parseInt(nativeVlanMatch[1]) === 1) {
                 nonCompliant.push({
                    severity: 'Alta',
                    context: block.trim().split('\n').filter(line => line.trim().startsWith('interface') || line.trim().includes('switchport trunk native vlan')).join('\n'),
                    recommendation: `Cambie la VLAN nativa para el trunk en la interfaz ${interfaceName} a una VLAN diferente a la por defecto (VLAN 1).`,
                    solution: `interface ${interfaceName}\n switchport trunk native vlan <nueva_vlan>`,
                    description: `La interfaz ${interfaceName} está configurada con la VLAN nativa por defecto (VLAN 1) en un trunk.`
                });
            }

            // Verificar si la interfaz no tiene configuración de VLAN explícita (implica VLAN 1 por defecto)
            const hasVlanConfig = accessVlanMatch || nativeVlanMatch || block.includes('switchport mode access') || block.includes('switchport mode trunk');
            const isShutdown = block.includes('shutdown');
            const isNoSwitchport = block.includes('no switchport');

            // Aplicar este análisis solo a interfaces que no sean VLAN
            if (!interfaceName.startsWith('Vlan') && !hasVlanConfig && !isShutdown && !isNoSwitchport) {
                 nonCompliant.push({
                    severity: 'Media',
                    context: block.trim().split('\n').filter(line => line.trim().startsWith('interface')).join('\n'),
                    recommendation: `Configure explícitamente la VLAN de acceso o nativa para la interfaz ${interfaceName}, o deshabilítela si no está en uso. Evite depender de la asignación implícita a la VLAN 1.`,
                    solution: `interface ${interfaceName}\n switchport access vlan <nueva_vlan> OR shutdown`,
                    description: `La interfaz ${interfaceName} no tiene una configuración de VLAN explícita y podría estar usando la VLAN 1 por defecto.`
                });
            }
        }
    });

    // Verificar si la VLAN 1 está presente en la configuración global de VLANs (aunque esto es común, es bueno mencionarlo)
    if (configText.includes('vlan 1')) {
        compliant.push('La VLAN 1 por defecto está presente en la configuración global de VLANs.');
    }


    return { compliant, nonCompliant };
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
    document.getElementById('export-json-btn').disabled = false;
    document.getElementById('export-csv-btn').disabled = false;


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

console.log("Verificando si jsPDF está disponible:", window.jspdf);
async function exportReport() {
    console.log("exportReport function called"); // Added console log
    const results = window.lastAnalysisResults;
    if (!results) {
        alert("No hay resultados de análisis para exportar. Por favor, analiza una configuración primero.");
        console.error("No analysis results available for export.");
        return;
    }
    console.log("Analysis results found:", results); // Added console log

    // Verificar que las librerías necesarias estén cargadas
    console.log("Estado de jspdf:", typeof jspdf, typeof jspdf?.jsPDF);
    if (typeof jspdf === 'undefined' || typeof jspdf.jsPDF === 'undefined') {
        alert("Error: jsPDF no está cargado. Asegúrese de que la biblioteca esté incluida.");
        console.error("jsPDF library not loaded.");
        return;
    }
    console.log("Estado de html2canvas:", typeof html2canvas);
    if (typeof html2canvas !== 'function') {
         alert("Error: html2canvas no está cargado. Asegúrese de que la biblioteca esté incluida.");
         console.error("html2canvas library not loaded.");
         return;
    }
     // jsPdfAutoTable extiende jsPDF, verificar si autoTable está disponible en una instancia de jsPDF
     const tempDocForCheck = new jspdf.jsPDF();
     console.log("Estado de autoTable en instancia de jsPDF:", typeof tempDocForCheck.autoTable);
     if (typeof tempDocForCheck.autoTable !== 'function') {
         alert("Error: jsPdfAutoTable no está cargado. Asegúrese de que la biblioteca esté incluida DESPUÉS de jsPDF.");
         console.error("jsPdfAutoTable library not loaded or not correctly attached to jsPDF.");
         return;
     }


    try { // Added try...catch block
        console.log("Inicializando jsPDF document.");
        // Inicializar PDF con orientación y unidad
        const doc = new jspdf.jsPDF({
            orientation: 'portrait',
            unit: 'mm',
            format: 'a4'
        });

        const pageWidth = doc.internal.pageSize.getWidth();
        const pageHeight = doc.internal.pageSize.getHeight();
        let y = 20; // Margen superior inicial

        const addHeader = () => {
            doc.setFontSize(10);
            doc.setTextColor(100);
            doc.text("Informe de Análisis Cisco", 14, 10);
            doc.text(`Fecha: ${new Date().toLocaleDateString()}`, pageWidth - 50, 10);
            doc.setDrawColor(200, 200, 200);
            doc.line(10, 12, pageWidth - 10, 12); // Línea divisoria
        };

        const addFooter = (page) => {
            doc.setFontSize(8);
            doc.setTextColor(150);
            doc.text("© CybersecurityJP - Analizador de Hardening Cisco", 10, pageHeight - 15);
            doc.text(`Página ${page}`, pageWidth - 30, pageHeight - 15);
        };

        // --- PORTADA ---
        addHeader();
        doc.setFontSize(20);
        doc.setTextColor(0, 70, 150);
        doc.text("Informe de Análisis Cisco", 60, y);
        y += 15;

        doc.setFontSize(12);
        doc.setTextColor(0);
        doc.text("Herramienta: CybersecurityJP - Evaluador de Configuraciones Cisco", 20, y);
        y += 10;
        doc.text(`Archivo: ${document.getElementById('file-name').textContent.replace('Archivo seleccionado: ', '')}`, 20, y);
        y += 10;
        doc.text(`Sistema Operativo: ${results.osType} / Versión: ${results.osVersion}`, 20, y);
        y += 10;
        doc.text(`Puntuación de Riesgo: ${results.riskScore}`, 20, y);
        y += 15;

        doc.addPage();

        // --- RESUMEN EJECUTIVO ---
        addHeader();
        y = 20;
        doc.setFontSize(16);
        doc.setTextColor(0, 70, 150);
        doc.text("Resumen Ejecutivo", 14, y);
        y += 10;

        doc.setFontSize(12);
        doc.setTextColor(0);
        doc.text(`Se han identificado ${results.nonCompliant.length} hallazgos de seguridad y ${results.compliant.length} puntos de cumplimiento.`, 14, y);
        y += 10;

        // Tabla de resumen
        console.log("Generando tabla de resumen con autoTable.");
        doc.autoTable({
            startY: y,
            head: [['Gravedad', 'Cantidad']],
            body: [
                ['Alta', results.severityCounts.Alta],
                ['Media', results.severityCounts.Media],
                ['Baja', results.severityCounts.Baja]
            ],
            theme: 'grid',
            styles: { fontSize: 10 },
            headStyles: { fillColor: [0, 100, 200] }
        });
        y = doc.lastAutoTable.finalY + 10;

        if (y > pageHeight - 40) {
            doc.addPage();
            y = 20;
        }

        // --- HALLAZGOS DE SEGURIDAD ---
        addHeader();
        doc.setFontSize(16);
        doc.setTextColor(0, 70, 150);
        doc.text("Hallazgos de Seguridad", 14, y);
        y += 10;

        const tableRows = results.nonCompliant.map(item => [
            item.severity,
            item.description,
            item.recommendation,
            item.solution
        ]);
        console.log("Datos para la tabla de hallazgos:", tableRows);

        doc.autoTable({
            startY: y,
            head: [['Gravedad', 'Descripción', 'Recomendación', 'Solución']],
            body: tableRows,
            theme: 'striped',
            styles: { fontSize: 9 },
            columnStyles: {
                0: { cellWidth: 20 },
                1: { cellWidth: 45 },
                2: { cellWidth: 45 },
                3: { cellWidth: 45 }
            },
            didDrawPage: function (data) {
                addFooter(data.pageNumber);
            }
        });

        // --- GRÁFICO DEL ANÁLISIS ---
        const canvas = document.getElementById('severityChart');
        if (canvas) {
            try { // Added try...catch for chart generation
                console.log("Generando imagen del gráfico con html2canvas.");
                const imgData = await html2canvas(canvas).then(canvas => canvas.toDataURL('image/png'));
                console.log("Imagen del gráfico generada.");
                const imgProps = doc.getImageProperties(imgData);
                const pdfWidth = pageWidth - 20;
                const imgWidth = pdfWidth;
                const imgHeight = (imgProps.height * imgWidth) / imgProps.width;

                doc.addPage();
                addHeader();
                y = 20;
                doc.setFontSize(16);
                doc.setTextColor(0, 70, 150);
                doc.text("Gráfico de Hallazgos por Gravedad", 14, y);
                y += 10;
                doc.addImage(imgData, 'PNG', 10, y, imgWidth, imgHeight);
            } catch (error) {
                console.error("Error al generar el gráfico:", error);
                // Optionally add text to the PDF indicating chart error
                // doc.text("Error al generar el gráfico.", 14, y + 10);
            }
        }


        // Guardar documento
        console.log("Guardando documento PDF.");
        doc.save("informe_analisis_cisco.pdf");

    } catch (error) { // Catch any errors during PDF generation
        console.error("Error durante la generación del PDF:", error);
        alert("Ocurrió un error al generar el informe PDF. Por favor, revisa la consola para más detalles.");
    }
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

// Function to export data as JSON
function exportJSON() {
    const data = window.lastAnalysisResults; // Get the last analysis results
    if (!data) {
        alert("No hay resultados de análisis para exportar a JSON.");
        return;
    }

    const jsonData = JSON.stringify(data, null, 2); // Convert data to JSON string with indentation
    const blob = new Blob([jsonData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'informe_analisis_cisco.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url); // Clean up the URL object
}

// Function to export data as CSV
function exportCSV() {
    const data = window.lastAnalysisResults; // Get the last analysis results
    if (!data || !data.nonCompliant || data.nonCompliant.length === 0) {
        alert("No hay hallazgos no conformes para exportar a CSV.");
        return;
    }

    const nonCompliant = data.nonCompliant;
    const header = ["Gravedad", "Descripción", "Contexto", "Recomendación", "Solución"];
    const rows = nonCompliant.map(item => [
        item.severity,
        item.description.replace(/,/g, ';').replace(/\n/g, ' '), // Replace commas and newlines in description
        item.context.replace(/,/g, ';').replace(/\n/g, ' '),     // Replace commas and newlines in context
        item.recommendation.replace(/,/g, ';').replace(/\n/g, ' '), // Replace commas and newlines in recommendation
        item.solution.replace(/,/g, ';').replace(/\n/g, ' ')      // Replace commas and newlines in solution
    ]);

    let csvContent = header.join(",") + "\n";
    rows.forEach(row => {
        csvContent += row.join(",") + "\n";
    });

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'hallazgos_no_conformes.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url); // Clean up the URL object
}


function analyzeUnusedInterfaces(configText) {
    const compliant = [];
    const nonCompliant = [];

    // Busca interfaces físicas en estado administrativo up pero operativo down
    const interfaceMatches = configText.match(/interface (\w+\d+)(?:\.\d+)?(?:[\s\S]*?)(?=\ninterface|\nend)/g) || [];

    for (const intf of interfaceMatches) {
        const nameMatch = intf.match(/interface (\S+)/);
        const interfaceName = nameMatch ? nameMatch[1] : null;
        const shutdownPresent = intf.includes('shutdown');
        const statusLine = intf.match(/(administratively down|down)/i);

        // Excluir interfaces VLAN
        if (interfaceName && interfaceName.startsWith('Vlan')) {
            continue;
        }

        if (interfaceName && statusLine && !shutdownPresent) {
            nonCompliant.push({
                severity: 'Media',
                context: intf.trim(),
                recommendation: `Deshabilite las interfaces no utilizadas con el comando "shutdown" y asigne a VLAN segura.`,
                solution: `${nameMatch[0]}\n shutdown\n switchport access vlan <vlan_segura>`,
                description: `La interfaz ${nameMatch[1]} está en estado "${statusLine[1]}" y no está deshabilitada con "shutdown".`
            });
        } else if (nameMatch && shutdownPresent) {
            compliant.push(`La interfaz ${nameMatch[1]} está deshabilitada correctamente.`);
        }
    }

    return { compliant, nonCompliant };
}
