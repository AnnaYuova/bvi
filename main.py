import re

def analyze_apache_config(config):
    # bezpecnostna analyza
    security_checks = [
        ('ServerName' not in config, "Missing ServerName directive for virtual host identification."),
        ('Listen' not in config, "Missing Listen directive to specify listening ports."),
        ('DocumentRoot' not in config, "Missing DocumentRoot directive to specify the web root directory."),
        ('DirectoryIndex' not in config, "Missing DirectoryIndex directive to specify default index file."),
        ('SSLCertificateFile' not in config, "SSL certificate not configured."),
        ('SSLCertificateKeyFile' not in config, "SSL certificate key not configured."),
        ('<Directory' not in config, "Missing <Directory> directive to restrict access."),
        ('MaxClients' not in config, "MaxClients directive not configured to limit connections."),
        ('LimitRequestBody' not in config, "LimitRequestBody directive not configured to limit request sizes.")
    ]

    # pripomienky na vylepsenie
    efficiency_recommendations = [
        ('ExpiresActive On' not in config, "Use the mod_expires to set expiration headers for static resources."),
        ('mod_deflate' not in config, "Enable mod_deflate or similar to compress response data."),
        ('KeepAlive On' not in config, "Set KeepAlive On to enable HTTP keep-alive and reduce latency."),
        ('Protocols http/2' not in config, "Consider enabling HTTP/2 protocol for improved performance."),
        ('AddOutputFilterByType' not in config, "Consider compressing static files using AddOutputFilterByType.")
    ]

    # osvedcene postupy
    best_practices = [
        ('Header set X-' not in config,
         "Add security headers such as X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy."),
        ('ServerTokens Prod' not in config, "Set ServerTokens to 'Prod' to minimize information leakage."),
        ('CustomLog' in config, "CustomLog is configured for request logging."),
        ('ErrorLog' in config, "ErrorLog is configured for error logging."),
        ('Header set Content-Security-Policy' not in config,
         "Implement Content Security Policy (CSP) to mitigate XSS attacks.")
    ]

    # kontrola syntaxe - regularne vyrazy
    def check_syntax(config):
        errors = []
        lines = config.splitlines()
        directive_pattern = re.compile(r'^\s*<\w+\s+.*?>\s*$|^\s*</\w+>\s*$|^\s*\w+\s+.*$')
        for line_number, line in enumerate(lines, 1):
            if line.strip() and not line.strip().startswith('#'):
                if not directive_pattern.match(line):
                    errors.append(f"Syntax error on line {line_number}: '{line.strip()}'")
        return errors

    output = ""
    for issue in security_checks:
        if issue[0]:
            output += f"Security Issue: {issue[1]}\n"
            output += f"Security Issue: {issue[1]}\n"

    for recommendation in efficiency_recommendations:
        if recommendation[0]:
            output += f"Efficiency Recommendation: {recommendation[1]}\n"

    for practice in best_practices:
        if practice[0]:
            output += f"Best Practice: {practice[1]}\n"

    syntax_errors = check_syntax(config)
    if syntax_errors:
        output += "Syntax Errors Found:\n" + "\n".join(syntax_errors) + "\n"
    else:
        output += "No Syntax Errors Found.\n"
    return output.strip()


def fix_apache_config(config_data):
    # tu sme si definovali tie zakladne prikazy, ktore musi obsahovat
    necessary_directives = {
        'ServerName': 'example.com',
        'Listen': '80',
        'DocumentRoot': '/var/www/html',
        'DirectoryIndex': 'index.html',
        'SSLCertificateFile': '/path/to/cert.pem',
        'SSLCertificateKeyFile': '/path/to/cert.key',
        'KeepAlive': 'On'
    }

    # rozdelim .config na riadky
    lines = config_data.splitlines()
    found_directives = {key: False for key in necessary_directives}

    # kontrolujem riadok po riadku prikazy, ktore uz su v .config
    for line in lines:
        for directive in necessary_directives:
            if line.strip().startswith(directive):
                found_directives[directive] = True

    # zistim, ktore prikazy treba doplnit a appendnem na koniec
    missing_directives = {key: value for key, value in necessary_directives.items() if not found_directives[key]}
    updated_config = config_data.strip() + '\n'

    if missing_directives:
        for directive, value in missing_directives.items():
            updated_config += f"{directive} {value}\n"
            print(f"Added missing {directive} directive with value: {value}")

    return updated_config


def read_config_file(filename):
    try:
        with open(filename, 'r') as file:
            return file.read()
    except FileNotFoundError:
        print(f"Error: The file '{filename}' does not exist.")
        return None

def save_config_to_file(config_text, filename):
    try:
        with open(filename, 'w') as file:
            file.write(config_text)
        print(f"Configuration saved to {filename}")
    except IOError as e:
        print(f"Error saving configuration to {filename}: {e}")


def main():
    config_filename = 'conf.txt'
    apache_conf = read_config_file(config_filename)
    if apache_conf is not None:
        print(apache_conf)

    # konfiguracny parser - zistim problemy
    print(analyze_apache_config(apache_conf))

    # oprava konfiguracneho suboru - zapise sa do txt conf2.txt
    fixed_config = fix_apache_config(apache_conf)
    if fixed_config is not None:
        save_config_to_file(fixed_config, 'conf2.txt')
    print(fixed_config)

if __name__ == "__main__":
    main()






