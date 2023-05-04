const core = require('@actions/core');
const axios = require('axios');


(async function main() {
    
    console.log("i'm here");
    let instanceUrl = core.getInput('instance-url', { required: true });
    const toolId = core.getInput('tool-id', { required: true });
    const username = core.getInput('devops-integration-user-name', { required: false });
    const password = core.getInput('devops-integration-user-password', { required: false });
    const secretToken = core.getInput('devops-security-token', { required: false });
    const jobname = core.getInput('job-name', { required: true });
    const projectKey = core.getInput('sonar-project-key', { required: true });
    let sonarUrl = core.getInput('sonar-host-url', { required: true });

    let githubContext = core.getInput('context-github', { required: true });
    console.log("Secret Token: "+secretToken+" ,username "+username);

    try {
        githubContext = JSON.parse(githubContext);
    } catch (e) {
        core.setFailed(`Exception parsing github context ${e}`);
    }
            
    let payload;
    
    try {
        sonarUrl = sonarUrl.trim();
        if (sonarUrl.endsWith('/'))
            sonarUrl = sonarUrl.slice(0, -1);

        instanceUrl = instanceUrl.trim();
        if (instanceUrl.endsWith('/'))
            instanceUrl = instanceUrl.slice(0, -1);

        payload = {
            toolId: toolId,
            runId: `${githubContext.run_id}`,
            runNumber: `${githubContext.run_number}`,
            runAttempt: `${githubContext.run_attempt}`,
            job: `${jobname}`,
            sha: `${githubContext.sha}`,
            workflow: `${githubContext.workflow}`,
            projectKey: `${projectKey}`,
            sonarUrl: `${sonarUrl}`,
            repository: `${githubContext.repository}`,
            ref: `${githubContext.ref}`,
            refName: `${githubContext.ref_name}`,
            refType: `${githubContext.ref_type}`
        };
        core.debug('Sonar Custon Action payload is : ${JSON.stringify(payload)}\n\n');
    } catch (e) {
        core.setFailed(`Exception setting the payload ${e}`);
        return;
    }

    let result;
    const endpointv1 = `${instanceUrl}/api/sn_devops/v1/devops/tool/softwarequality?toolId=${toolId}`;
    const endpointv2 = `${instanceUrl}/api/sn_devops/devops/tool/softwarequality?toolId=${toolId}`;
    let endpoint;
    let httpHeaders;
    
    function getSHA256GithubSignature(dbToken, requestBody) {
        let sha256Token = '';
        let scriptJSCode = 'function getAuthenticationToken(dbToken, requestBody) {\n' + '    var shaAlgorithm = \'HmacSHA256\';\n' + '    \n' + '    var calculatedSignature = this._prepareSignature(dbToken, JSON.stringify(requestBody), shaAlgorithm);\n' + '    calculatedSignature = \'sha256=\' + calculatedSignature;\n' + '    return calculatedSignature;\n' + '}\n' + '\n' + 'function _prepareSignature(secret, payload, shaAlgorithm) {\n' + '    var base64EncodedSignature = CertificateEncryption.generateMac(gs.base64Encode(secret), shaAlgorithm, payload);\n' + '    //gs.info(\'base64EncodedSignature : \'+ base64EncodedSignature);\n' + '    return this._base64toHex(base64EncodedSignature);\n' + '}\n' + '\n' + 'function _base64toHex(base64Signatrue) {\n' + '    var base64Alphabet = \'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\';\n' + '    var base64Lookup = {};\n' + '    for (var i = 0; i < base64Alphabet.length; i++)\n' + '        base64Lookup[base64Alphabet.charAt(i)] = i;\n' + '    base64Lookup[\'=\'] = 0;\n' + '\n' + '    var hexAlphabet = \'0123456789abcdef\';\n' + '\n' + '    var pad = 0;\n' + '    if (base64Signatrue.charAt(base64Signatrue.length - 1) === \'=\') {\n' + '        pad++;\n' + '\n' + '        if (base64Signatrue.charAt(base64Signatrue.length - 2) === \'=\')\n' + '            pad++;\n' + '    }\n' + '\n' + '    var hex = [];\n' + '\n' + '    var idx = 0;\n' + '    while (idx < base64Signatrue.length) {\n' + '        var bits = 0;\n' + '        bits |= base64Lookup[base64Signatrue.charAt(idx++)] << 18;\n' + '        bits |= base64Lookup[base64Signatrue.charAt(idx++)] << 12;\n' + '        bits |= base64Lookup[base64Signatrue.charAt(idx++)] << 6;\n' + '        bits |= base64Lookup[base64Signatrue.charAt(idx++)];\n' + '\n' + '        hex.push(hexAlphabet[(bits >> 20) & 0xF]);\n' + '        hex.push(hexAlphabet[(bits >> 16) & 0xF]);\n' + '\n' + '        if (idx != base64Signatrue.length || pad < 2) {\n' + '            hex.push(hexAlphabet[(bits >> 12) & 0xF]);\n' + '            hex.push(hexAlphabet[(bits >> 8) & 0xF]);\n' + '        }\n' + '\n' + '        if (idx != base64Signatrue.length || pad < 1) {\n' + '            hex.push(hexAlphabet[(bits >> 4) & 0xF]);\n' + '            hex.push(hexAlphabet[bits & 0xF]);\n' + '        }\n' + '    }\n' + '\n' + '    return hex.join(\'\');\n' + '};\n' + 'var key = \'' + dbToken + '\';\n' + 'var payload = ' + requestBody + ';\n' + 'var generatedSignatureValue = getAuthenticationToken(key,payload);\n' + 'gs.info(generatedSignatureValue);';
        try {
          let script = new Script(scriptJSCode, 900000);
          script.scope('34cfa6f087302300f97abba826cb0b54');
          sha256Token = script.runWithScriptOutput();
        } catch (e) {
          assertTrue('Script execution for the invokeDiscover resulted in exception', false);
        }
        sha256Token = sha256Token.substring(11);
        return sha256Token;
      }

    try {
        if (secretToken) {
            const sha256TokenGithubSignature = getSHA256GithubSignature(secretToken, JSON.stringify(payload));
            console.log(sha256TokenGithubSignature);
            const defaultHeadersv2 = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                // 'Authorization': 'sn_devops.DevOpsToken '+`${secretToken}`+' '+`${toolId}`,
                'x-hub-signature-256': `${sha256TokenGithubSignature}`
                //  'token': `${ni.nolog.token}`
                //'Authorization': 'x-hub-signature-256 '+`${secretToken}`
            };
            httpHeaders = {
                headers: defaultHeadersv2
            };
            endpoint = endpointv2;
            console.log("Secret Token if code ");
        }
        else if (username && password) {
            const token = `${username}:${password}`;
            const encodedToken = Buffer.from(token).toString('base64');
            const defaultHeadersv1 = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': 'Basic ' + `${encodedToken}`
            };
            httpHeaders = {
                headers: defaultHeadersv1
            };
            endpoint = endpointv1;
            console.log("username and password if code ");
        } else {
            throw "Credentials are empty";
        }
        console.log("endpoint: "+endpoint);
        snowResponse = await axios.post(endpoint, JSON.stringify(payload), httpHeaders);
    } catch (e) {
        if (e.message.includes('ECONNREFUSED') || e.message.includes('ENOTFOUND') || e.message.includes('405')) {
            core.setFailed('ServiceNow Instance URL is NOT valid. Please correct the URL and try again.');
        } else if (e.message.includes('401')) {
            core.setFailed('Invalid Credentials. Please correct the credentials and try again.');
        } else {
            core.setFailed(`ServiceNow Software Quality Results are NOT created. Please check ServiceNow logs for more details.`);
        }
    }
    
})();



