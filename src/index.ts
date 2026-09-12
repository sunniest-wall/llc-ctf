import express, { Request, Response } from 'express';
import { exec } from 'child_process';

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse URL-encoded bodies (form data)
app.use(express.urlencoded({ extended: true }));

const HTML_TEMPLATE = `
<!DOCTYPE html>
<html>
<head>
    <title>LLC Secure Network Pinger (TS Edition)</title>
    <style>
        body { font-family: monospace; background-color: #121212; color: #00ff00; padding: 20px; }
        input[type="text"] { background: #222; border: 1px solid #00ff00; color: #00ff00; padding: 5px; width: 250px;}
        input[type="submit"] { background: #00ff00; color: #121212; border: none; padding: 5px 15px; cursor: pointer; }
        .error { color: #ff0000; font-weight: bold; }
    </style>
</head>
<body>
    <h2>[ LLC Secure Diagnostics v2 - Node.js ]</h2>
    <p>Ping a remote server. Now with next-gen WAF protection.</p>
    <form method="POST">
        Target IP: <input type="text" name="ip" placeholder="127.0.0.1">
        <input type="submit" value="Execute Ping">
    </form>
    <br>
    <pre>__OUTPUT__</pre>
</body>
</html>
`;

app.get('/', (req: Request, res: Response) => {
    res.send(HTML_TEMPLATE.replace('__OUTPUT__', ''));
});

app.post('/', (req: Request, res: Response) => {
    const ip: string = req.body.ip || '';
    
    // The WAF Blacklist
    const blacklist = [';', '|', '&', 'cat', 'flag', 'ls'];
    
    // Check against blacklist (case-insensitive)
    for (const badWord of blacklist) {
        if (ip.toLowerCase().includes(badWord)) {
            const errorMsg = `<span class='error'>[!] WAF ALERT: Forbidden character or word '${badWord}' detected. Incident logged.</span>`;
            return res.send(HTML_TEMPLATE.replace('__OUTPUT__', errorMsg));
        }
    }

    // Vulnerable sink: passing user input directly to the shell
    const pingFlag = process.platform === "win32" ? "-n" : "-c";
    const cmd = `ping ${pingFlag} 3 ${ip}`;    
    exec(cmd, (error, stdout, stderr) => {
        // In case of error (like an invalid ping or injected command failing partway), 
        // we still want to return the output so the player can see the results of their injection.
        const output = error ? (stdout || stderr || error.message) : stdout;
        res.send(HTML_TEMPLATE.replace('__OUTPUT__', output));
    });
});

app.listen(PORT, () => {
    console.log(`[+] LLC Pinger listening on port ${PORT}`);
});