#!/usr/bin/perl
use Encode;
use strict;
use warnings;
use Getopt::Long;
use LWP::UserAgent;
use URI;
use HTML::TreeBuilder;
use Text::Table;
use POSIX qw(strftime);

# Set the encoding for STDOUT to UTF-8
binmode(STDOUT, ':encoding(UTF-8)');

# [SNIPPET] Global Exploit/Success Pattern
# Customize the pattern to match any text that indicates a payload was successful:


# Banner text
my $banner = <<'BANNER';

*********************************************************************
*                                                                   *
*  - Attack Surface and Security Assessment Tool                    *
*                                                                   *
*  Author:                                                          *
*  - Haroon Ahmad Awan                                              *
*                                                                   *
*  Features:                                                        *
*  - Assessing configurations, assessing rules                      *
*  - View possible issuess in critical infrastructure               *
*  - Vulnerability Surface View                                     *
*  - Possibility of Anomalies by using unique algorithm             *
*                                                                   *
*  Description:                                                     *
*  Code for identifying vulnerabilities on web server               *
*  Code for identifying vulnerabilities on web application          *
*  Detect potential threats in web applications and server          *
*  Detect anomalies in web applications and server responses        *
*                                                                   *
*  Reports:                                                         *
*  Go to the output directory view an HTML                          * 
*  Results show as tabular format in the command-line interface     * 
*                                                                   *
*********************************************************************

BANNER

# Print the banner
print $banner;

# Constants
use constant {
    VULNERABILITIES_LOG => 'vulnerabilities.log',
    PERMISSIONS_LOG     => 'permissions.log',
    OUTPUT_FOLDER       => 'output',
};

# Global variables
my $base_url; # Base URL for domain-specific crawling
my %visited_urls;
my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
my $content; # Content variable added


# Function to display a message
sub display_message {
    my ($severity, $message) = @_;
    print "[$timestamp] [$severity] $message\n";
}

# Function to parse HTML content
sub parse_html {
    my ($content) = @_;
    my $parser = HTML::TreeBuilder->new;
    $parser->store_comments(1);
    $parser->parse($content);
    return $parser;
}

# Function to extract links from an HTML page
sub extract_links {
    my ($url, $content) = @_;
    my $parser = parse_html($content);
    my @links;

    # Extract links from anchor tags
    my @a_tags = $parser->look_down(_tag => 'a');
    foreach my $a (@a_tags) {
        my $href = $a->attr('href');
        if ($href) {
            my $abs_url = eval { URI->new_abs($href, $url)->canonical };
            if ($abs_url) {
                push @links, $abs_url->as_string;
            } else {
                print "[Error] [$timestamp] Invalid URL: $href\n\n";
            }
        }
    }

    return \@links;  # Return an array reference
}

# Function to log discovered links
sub log_links {
    my ($links_log, $url, $links) = @_;
    open(my $fh, '>>', $links_log) or die "[Error] [$timestamp] Cannot open $links_log: $!";
    foreach my $link (@$links) {
        print $fh "$url => $link\n";
    }
    close($fh);
}

# Define the handle_vulnerability subroutine
sub handle_vulnerability {
    my ($vulnerability_name, $url, $vulnerabilities_log, $payload) = @_;

    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
    # If $payload is undef, set it to "[N/A]"
    $payload = defined $payload ? $payload : '[N/A]';

    open(my $vulnerabilities_log_file, '>>', $vulnerabilities_log)
        or die "[Error] [$timestamp] Cannot open vulnerabilities log file: $!";

    print $vulnerabilities_log_file
        "[$timestamp] [Vulnerability: $vulnerability_name] ",
        "[URL: $url] ",
        "[Payload: $payload]\n";

    close($vulnerabilities_log_file);

    print "\n[Vulnerability] [$timestamp] $vulnerability_name on $url\n",
          "    Payload used: $payload\n\n";
}



# Define the anomailies subroutine
sub is_anomaly_v1 {
    my ($content, $status_code, $pattern, $dom_elements_found) = @_;

    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);

    # Check if the content is not empty, and there's no payload
    if ($content || $content !~ /\w/) {
     # print "[No Anomaly] [$timestamp] Content is not empty, and there's no payload\n";
        return 0;
    }

    # Check if the response content matches the vulnerability pattern
    if ($content =~ /<script[^>]*>(?:(?!<\/script>).)*hello this is alert box exploit/i ||
        $content =~ /alert\s*\(\s*'[^']*hello this is alert box exploit[^']*'\s*\)/i ||
        $content =~ /eval\s*\(\s*'[^']*hello this is alert box exploit[^']*'\s*\)/i) {
        print "[Anomaly] [$timestamp] Vulnerability pattern detected in the response content\n";
        return 1;
    }

    # Initial condition: If the status code is 200 and there's no payload, return 0
    if ($status_code == 200 && (!defined $content || $content !~ /\w/)) {
        # print "[No Anomaly] [$timestamp] HTTP status code is 200, but the content is empty\n";
        return 0;
    }

    # Additional conditions:

    # 1. If the status code is 200 and there are more than 400 lines within HTML, body, or head tags, return 0
    if ($status_code == 200) {
        if ($dom_elements_found && $content =~ /<html.*?<\/html>/s) {
            my $html_content = $&;
            my $line_count = () = $html_content =~ /\n/g;  # Counting the number of lines
            if ($line_count > 400) {
                return 0;  # Returning 0 if there are more than 400 lines
            }
        }
    }

    # 2. If the status code is 200 and there are exactly 15 lines within HTML, body, or head tags, return 0
    if ($status_code == 200) {
        if ($dom_elements_found && $content =~ /<html.*?<\/html>/s) {
            my $html_content = $&;
            my $line_count = () = $html_content =~ /\n/g;  # Counting the number of lines
            if ($line_count == 15) {
                return 0;  # Returning 0 if there are exactly 15 lines
            }
        }
    }

    # 3. If the status code is 400 and there are more than 400 lines within HTML, body, or head tags, return 0
    if ($status_code == 400) {
        if ($dom_elements_found && $content =~ /<html.*?<\/html>/s) {
            my $html_content = $&;
            my $line_count = () = $html_content =~ /\n/g;  # Counting the number of lines
            if ($line_count > 400) {
                return 0;  # Returning 0 if there are more than 400 lines
            }
        }
    }

    # 4. If the status code is 400 and there are exactly 15 lines within HTML, body, or head tags, return 0
    if ($status_code == 400) {
        if ($dom_elements_found && $content =~ /<html.*?<\/html>/s) {
            my $html_content = $&;
            my $line_count = () = $html_content =~ /\n/g;  # Counting the number of lines
            if ($line_count == 15) {
                return 0;  # Returning 0 if there are exactly 15 lines
            }
        }
    }

    # 5. If the status code is 302 and there are more than 400 lines within HTML, body, or head tags, return 0
    if ($status_code == 302) {
        if ($dom_elements_found && $content =~ /<html.*?<\/html>/s) {
            my $html_content = $&;
            my $line_count = () = $html_content =~ /\n/g;  # Counting the number of lines
            if ($line_count > 400) {
                return 0;  # Returning 0 if there are more than 400 lines
            }
        }
    }
 

    # 6. If the status code is 302 and there are exactly 15 lines within HTML, body, or head tags, return 0
    if ($status_code == 302) {
        if ($dom_elements_found && $content =~ /<html.*?<\/html>/s) {
            my $html_content = $&;
            my $line_count = () = $html_content =~ /\n/g;  # Counting the number of lines
            if ($line_count == 15) {
                return 0;  # Returning 0 if there are exactly 15 lines
            }
        }
    }

    # Additional comments can be added to explain the purpose of each condition

    # Check if the status code is 200, and the content doesn't contain '<script>'
    if ($status_code == 200 && (!defined $content || $content !~ /<script>/i)) {
     # print "[No Anomaly] [$timestamp] HTTP status code is 200, and there's no <script> tag in the content\n";
        return 0;
    }

    # Check if the status code is 200 and the content is empty, and there's no payload
    if ($status_code == 200 && (!defined $content || $content !~ /\w/)) {
     # print "[No Anomaly] [$timestamp] HTTP status code is 200, but the content is empty\n";
        return 0;
    }

    # Check if the status code is 403 and the content is empty, and there's no payload
    if ($status_code == 403 && (!defined $content || $content !~ /\w/)) {
     # print "[No Anomaly] [$timestamp] HTTP status code is 200, but the content is empty\n";
        return 0;
    }

    # Check if the status code is 400 and the content is empty, and there's no payload
    if ($status_code == 400 && (!defined $content || $content !~ /\w/)) {
     # print "[No Anomaly] [$timestamp] HTTP status code is 200, but the content is empty\n";
        return 0;
    }

    # Check if the status code is 302 and the content is empty, and there's no payload
    if ($status_code == 302 && (!defined $content || $content !~ /\w/)) {
     # print "[No Anomaly] [$timestamp] HTTP status code is 200, but the content is empty\n";
        return 0;
    }

    # Check if the status code is 302
    if ($status_code == 302) {
        return 0;  # Return 0 if status code is 302
    }

    # Check if "challenge" or "robot" is present in the content
    if (defined $dom_elements_found && $content && ($content =~ /challenge/i || $content =~ /robot/i || $content =~ /Found/i || $content =~ /found/i)) {
        return 0;  # Return 0 if "challenge" or "robot" is found in the content
    }

    # Check if DOM elements are found and there's no payload in the content
    if ($dom_elements_found && (!defined $content || $content !~ /\w/)) {
     # print "[No Anomaly] [$timestamp] DOM elements are found, but there's no payload in the content\n";
        return 0;
    }

    # Check if the response content matches the vulnerability pattern
    if ($dom_elements_found && $content =~ /<script[^>]*>(?:(?!<\/script>).)*hello this is alert box exploit/i ||
        $dom_elements_found && $content =~ /alert\s*\(\s*'[^']*hello this is alert box exploit[^']*'\s*\)/i ||
        $dom_elements_found && $content =~ /eval\s*\(\s*'[^']*hello this is alert box exploit[^']*'\s*\)/i) {
        print "[Anomaly] [$timestamp] Vulnerability pattern detected in the response content\n";
        return 1;
    }

    # Check if the response content matches the vulnerability pattern
    if ($dom_elements_found && $content =~ /$pattern/i) {
        print "[Anomaly] [$timestamp] Vulnerability pattern detected in the response content\n";
        return 1;
    }

    # Check if the response content contains the pattern within div tags
    if ($status_code == 200 && $dom_elements_found && $content =~ /<[^>]*$pattern/i) {
    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
        # print "[No Anomaly] [$timestamp] Vulnerability pattern detected within div tags in the response content\n";
    return 0;  
    }

    # Check if the response content contains the pattern within div tags
    if ($status_code == 403 && $dom_elements_found && $content =~ /<[^>]*$pattern/i) {
    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
        # print "[No Anomaly] [$timestamp] Vulnerability pattern detected within div tags in the response content\n";
    return 0;  
    }

    # Check if the response content contains the pattern within div tags
    if ($status_code == 400 && $dom_elements_found && $content =~ /<[^>]*$pattern/i) {
    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
        # print "[No Anomaly] [$timestamp] Vulnerability pattern detected within div tags in the response content\n";
    return 0;  
    }

    # Initial condition: If the status code is 200 and there's no payload, return 0
    if ($status_code == 200 && (!defined $dom_elements_found && $content || $dom_elements_found && $content !~ /\w/)) {
        # print "[No Anomaly] [$timestamp] HTTP status code is 200, but the content is empty\n";
        return 0;
    }

    # Check if the response content contains the pattern within div tags
    if ($status_code == 302 && $dom_elements_found && $content =~ /<[^>]*$pattern/i) {
    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
        # print "[No Anomaly] [$timestamp] Vulnerability pattern detected within div tags in the response content\n";
    return 0;  
    }

    my @patterntoscantodetect = (
      'COMMAND', 'INJECTION', 'XSS', 'DOM', 'XSS', 'SQL', 'INJECTION', 'FILE', 'INCLUSION', 'DIRECTORY', 'TRAVERSAL', 'REMOTE', 'FILE', 'INCLUSION', 'CROSS-SITE', 'REQUEST', 'FORGERY', '\(CSRF\)', 'UNRESTRICTED', 'FILE', 'UPLOAD', 'PASSWORD', 'CRACKING', 'SESSION', 'HIJACKING', 'BROKEN', 'AUTH', 'AND', 'SESSION', 'MANAGEMENT', 'REMOTE', 'CODE', 'EXECUTION', 'LOCAL', 'FILE', 'INCLUSION', 'SERVER', 'SIDE', 'REQUEST', 'FORGERY', '\(SSRF\)', 'XML', 'EXTERNAL', 'ENTITY', '\(XXE\)', 'INJECTION', 'CROSS-SITE', 'SCRIPT', 'INCLUSION', '\(XSSI\)', 'LDAP', 'INJECTION', 'XPATH', 'INJECTION', 'OBJECT', 'INJECTION', 'CROSS-DOMAIN', 'SCRIPTING', 'HTTP', 'RESPONSE', 'SPLITTING', 'BUFFER', 'OVERFLOW', 'INSECURE', 'CRYPTOGRAPHIC', 'STORAGE', 'INSECURE', 'DIRECT', 'OBJECT', 'REFERENCES', 'INSUFFICIENT', 'LOGGING', 'AND', 'MONITORING', 'SECURITY', 'MISCONFIGURATION', 'CROSS-SITE', 'SCRIPT', 'INCLUSION', '\(CSSI\)', 'CLICK', 'FRAUD', 'BROKEN', 'ACCESS', 'CONTROL', 'CLICKJACKING', 'HIDDEN', 'FORM', 'FIELDS', 'SHELLSHOCK', 'SERVER-SIDE', 'TEMPLATE', 'INJECTION', '\(SSTI\)', 'CODE', 'INJECTION', 'SESSION', 'FIXATION', 'SOAP', 'INJECTION', 'HTML', 'INJECTION', 'DOM-BASED', 'XSS', 'RFI', '\(REMOTE', 'FILE', 'INCLUSION\)', 'IDOR', '\(INSECURE', 'DIRECT', 'OBJECT', 'REFERENCE\)', 'DIRECTORY', 'TRAVERSAL', 'WEB', 'CACHE', 'POISONING', 'HIDDEN', 'FIELD', 'TAMPERING', 'CONNECTION', 'STRING', 'PARAMETER', 'POLLUTION', 'CRLF', 'INJECTION', 'XXE', '\(XML', 'EXTERNAL', 'ENTITY\)', 'INJECTION', 'SSRF', '\(SERVER-SIDE', 'REQUEST', 'FORGERY\)', 'XSS', '\(CROSS-SITE', 'SCRIPTING\)', 'RCE', '\(REMOTE', 'CODE', 'EXECUTION\)', 'UNRESTRICTED', 'FILE', 'UPLOAD', 'PASSWORD', 'CRACKING', 'SESSION', 'HIJACKING', 'BROKEN', 'AUTH', 'AND', 'SESSION', 'MANAGEMENT', 'Command', 'Injection', 'Xss', 'Dom', 'Xss', 'Sql', 'Injection', 'File', 'Inclusion', 'Directory', 'Traversal', 'Remote', 'File', 'Inclusion', 'Cross-Site', 'Request', 'Forgery', '\(Csrf\)', 'Unrestricted', 'File', 'Upload', 'Password', 'Cracking', 'Session', 'Hijacking', 'Broken', 'Auth', 'And', 'Session', 'Management', 'Remote', 'Code', 'Execution', 'Local', 'File', 'Inclusion', 'Server', 'Side', 'Request', 'Forgery', '\(Ssrf\)', 'Xml', 'External', 'Entity', '\(Xxe\)', 'Injection', 'Cross-Site', 'Script', 'Inclusion', '\(Xssi\)', 'Ldap', 'Injection', 'Xpath', 'Injection', 'Object', 'Injection', 'Cross-Domain', 'Scripting', 'Http', 'Response', 'Splitting', 'Buffer', 'Overflow', 'Insecure', 'Cryptographic', 'Storage', 'Insecure', 'Direct', 'Object', 'References', 'Insufficient', 'Logging', 'And', 'Monitoring', 'Security', 'Misconfiguration', 'Cross-Site', 'Script', 'Inclusion', '\(Cssi\)', 'Click', 'Fraud', 'Broken', 'Access', 'Control', 'Clickjacking', 'Hidden', 'Form', 'Fields', 'Shellshock', 'Server-Side', 'Template', 'Injection', '\(Ssti\)', 'Code', 'Injection', 'Session', 'Fixation', 'Soap', 'Injection', 'Html', 'Injection', 'Dom-Based', 'Xss', 'Rfi', '\(Remote', 'File', 'Inclusion\)', 'Idor', '\(Insecure', 'Direct', 'Object', 'Reference\)', 'Directory', 'Traversal', 'Web', 'Cache', 'Poisoning', 'Hidden', 'Field', 'Tampering', 'Connection', 'String', 'Parameter', 'Pollution', 'Crlf', 'Injection', 'Xxe', '\(Xml', 'External', 'Entity\)', 'Injection', 'Ssrf', '\(Server-Side', 'Request', 'Forgery\)', 'Xss', '\(Cross-Site', 'Scripting\)', 'Rce', '\(Remote', 'Code', 'Execution\)', 'Unrestricted', 'File', 'Upload', 'Password', 'Cracking', 'Session', 'Hijacking', 'Broken', 'Auth', 'And', 'Session', 'Management', 'command', 'injection', 'xss', 'dom', 'xss', 'sql', 'injection', 'file', 'inclusion', 'directory', 'traversal', 'remote', 'file', 'inclusion', 'cross-site', 'request', 'forgery', '\(csrf\)', 'unrestricted', 'file', 'upload', 'password', 'cracking', 'session', 'hijacking', 'broken', 'auth', 'and', 'session', 'management', 'remote', 'code', 'execution', 'local', 'file', 'inclusion', 'server', 'side', 'request', 'forgery', '\(ssrf\)', 'xml', 'external', 'entity', '\(xxe\)', 'injection', 'cross-site', 'script', 'inclusion', '\(xssi\)', 'ldap', 'injection', 'xpath', 'injection', 'object', 'injection', 'cross-domain', 'scripting', 'http', 'response', 'splitting', 'buffer', 'overflow', 'insecure', 'cryptographic', 'storage', 'insecure', 'direct', 'object', 'references', 'insufficient', 'logging', 'and', 'monitoring', 'security', 'misconfiguration', 'cross-site', 'script', 'inclusion', '\(cssi\)', 'click', 'fraud', 'broken', 'access', 'control', 'clickjacking', 'hidden', 'form', 'fields', 'shellshock', 'server-side', 'template', 'injection', '\(ssti\)', 'code', 'injection', 'session', 'fixation', 'soap', 'injection', 'html', 'injection', 'dom-based', 'xss', 'rfi', '\(remote', 'file', 'inclusion\)', 'idor', '\(insecure', 'direct', 'object', 'reference\)', 'directory', 'traversal', 'web', 'cache', 'poisoning', 'hidden', 'field', 'tampering', 'connection', 'string', 'parameter', 'pollution', 'crlf', 'injection', 'xxe', '\(xml', 'external', 'entity\)', 'injection', 'ssrf', '\(server-side', 'request', 'forgery\)', 'xss', '\(cross-site', 'scripting\)', 'rce', '\(remote', 'code', 'execution\)', 'unrestricted', 'file', 'upload', 'password', 'cracking', 'session', 'hijacking', 'broken', 'auth', 'and', 'session', 'management'

    );

    my $patterntoscan = join('|', map { quotemeta } @patterntoscantodetect);

    # Check if the response content contains the patterntoscan within div tags
    if ($status_code == 200 && $dom_elements_found && $content =~ /($patterntoscan)/i) {
        # print "[No Anomaly] [$timestamp] Vulnerability pattern detected within div tags in the response content\n";
        return 0;
    }


    # print "[Info] [$timestamp] No anomalies detected in any case!\n";
    return 0;  # Default case: not an anomaly
}





sub is_anomaly_v2 {
    my ($content, $status_code, $pattern) = @_;

    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);

    # Check if the content is not empty, and there's no payload
    if ($content || $content !~ /\w/) {
        # print "[No Anomaly] [$timestamp] Content is not empty, and there's no payload\n";
        return 0;
    }

    # Check if the status code is 302
    if ($status_code == 302) {
        return 0;  # Return 0 if status code is 302
    }

    # Check if "challenge" or "robot" is present in the content
    if (defined $content && ($content =~ /challenge/i || $content =~ /robot/i || $content =~ /Found/i || $content =~ /found/i)) {
        return 0;  # Return 0 if "challenge" or "robot" is found in the content
    }


        # Additional conditions:

    # 1. If the status code is 200 and there are more than 400 lines within HTML, body, or head tags, return 0
    if ($status_code == 200) {
        if ($content =~ /<html.*?<\/html>/s) {
            my $html_content = $&;
            my $line_count = () = $html_content =~ /\n/g;  # Counting the number of lines
            if ($line_count > 400) {
                return 0;  # Returning 0 if there are more than 400 lines
            }
        }
    }

    # 2. If the status code is 200 and there are exactly 15 lines within HTML, body, or head tags, return 0
    if ($status_code == 200) {
        if ($content =~ /<html.*?<\/html>/s) {
            my $html_content = $&;
            my $line_count = () = $html_content =~ /\n/g;  # Counting the number of lines
            if ($line_count == 15) {
                return 0;  # Returning 0 if there are exactly 15 lines
            }
        }
    }

    # 3. If the status code is 400 and there are more than 400 lines within HTML, body, or head tags, return 0
    if ($status_code == 400) {
        if ($content =~ /<html.*?<\/html>/s) {
            my $html_content = $&;
            my $line_count = () = $html_content =~ /\n/g;  # Counting the number of lines
            if ($line_count > 400) {
                return 0;  # Returning 0 if there are more than 400 lines
            }
        }
    }

    # 4. If the status code is 400 and there are exactly 15 lines within HTML, body, or head tags, return 0
    if ($status_code == 400) {
        if ($content =~ /<html.*?<\/html>/s) {
            my $html_content = $&;
            my $line_count = () = $html_content =~ /\n/g;  # Counting the number of lines
            if ($line_count == 15) {
                return 0;  # Returning 0 if there are exactly 15 lines
            }
        }
    }

    # 5. If the status code is 302 and there are more than 400 lines within HTML, body, or head tags, return 0
    if ($status_code == 302) {
        if ($content =~ /<html.*?<\/html>/s) {
            my $html_content = $&;
            my $line_count = () = $html_content =~ /\n/g;  # Counting the number of lines
            if ($line_count > 400) {
                return 0;  # Returning 0 if there are more than 400 lines
            }
        }
    }

    # 6. If the status code is 302 and there are exactly 15 lines within HTML, body, or head tags, return 0
    if ($status_code == 302) {
        if ($content =~ /<html.*?<\/html>/s) {
            my $html_content = $&;
            my $line_count = () = $html_content =~ /\n/g;  # Counting the number of lines
            if ($line_count == 15) {
                return 0;  # Returning 0 if there are exactly 15 lines
            }
        }
    }

    # Check if the status code is 403 and the content is empty, and there's no payload
    if ($status_code == 403 && (!defined $content || $content !~ /\w/)) {
        # print "[No Anomaly] [$timestamp] HTTP status code is 200, but the content is empty\n";
        return 0;
    }

    # Check if the status code is 400 and the content is empty, and there's no payload
    if ($status_code == 400 && (!defined $content || $content !~ /\w/)) {
        # print "[No Anomaly] [$timestamp] HTTP status code is 200, but the content is empty\n";
        return 0;
    }

    # Check if the status code is 200 and the content is empty, and there's no payload
    if ($status_code == 200 && (!defined $content || $content !~ /\w/)) {
        # print "[No Anomaly] [$timestamp] HTTP status code is 200, but the content is empty\n";
        return 0;
    }



    # Check if the response content matches the vulnerability pattern
    if ($content =~ /<script[^>]*>(?:(?!<\/script>).)*hello this is alert box exploit/i ||
        $content =~ /alert\s*\(\s*'[^']*hello this is alert box exploit[^']*'\s*\)/i ||
        $content =~ /eval\s*\(\s*'[^']*hello this is alert box exploit[^']*'\s*\)/i) {
        print "[Anomaly] [$timestamp] Vulnerability pattern detected in the response content\n";
        return 1;
    }

    # Check if the response content matches the vulnerability pattern
    if ($content =~ /$pattern/i) {
        print "[Anomaly] [$timestamp] Vulnerability pattern detected in the response content\n";
        return 1;
    }

    # Check if the response content contains the pattern within div tags
    if ($status_code == 200 && $content =~ /<[^>]*$pattern/i) {
        # print "[No Anomaly] [$timestamp] Vulnerability pattern detected within div tags in the response content\n";
        return 0;
    }

    # Check if the response content contains the pattern within div tags
    if ($status_code == 400 && $content =~ /<[^>]*$pattern/i) {
        # print "[No Anomaly] [$timestamp] Vulnerability pattern detected within div tags in the response content\n";
        return 0;
    }

    # Check if the response content contains the pattern within div tags
    if ($status_code == 302 && $content =~ /<[^>]*$pattern/i) {
        # print "[No Anomaly] [$timestamp] Vulnerability pattern detected within div tags in the response content\n";
        return 0;
    }

    # Check if the response content contains the pattern within div tags
    if ($status_code == 403 && $content =~ /<[^>]*$pattern/i) {
        # print "[No Anomaly] [$timestamp] Vulnerability pattern detected within div tags in the response content\n";
        return 0;
    }

    my @patterntoscantodetectab = (
      'COMMAND', 'INJECTION', 'XSS', 'DOM', 'XSS', 'SQL', 'INJECTION', 'FILE', 'INCLUSION', 'DIRECTORY', 'TRAVERSAL', 'REMOTE', 'FILE', 'INCLUSION', 'CROSS-SITE', 'REQUEST', 'FORGERY', '\(CSRF\)', 'UNRESTRICTED', 'FILE', 'UPLOAD', 'PASSWORD', 'CRACKING', 'SESSION', 'HIJACKING', 'BROKEN', 'AUTH', 'AND', 'SESSION', 'MANAGEMENT', 'REMOTE', 'CODE', 'EXECUTION', 'LOCAL', 'FILE', 'INCLUSION', 'SERVER', 'SIDE', 'REQUEST', 'FORGERY', '\(SSRF\)', 'XML', 'EXTERNAL', 'ENTITY', '\(XXE\)', 'INJECTION', 'CROSS-SITE', 'SCRIPT', 'INCLUSION', '\(XSSI\)', 'LDAP', 'INJECTION', 'XPATH', 'INJECTION', 'OBJECT', 'INJECTION', 'CROSS-DOMAIN', 'SCRIPTING', 'HTTP', 'RESPONSE', 'SPLITTING', 'BUFFER', 'OVERFLOW', 'INSECURE', 'CRYPTOGRAPHIC', 'STORAGE', 'INSECURE', 'DIRECT', 'OBJECT', 'REFERENCES', 'INSUFFICIENT', 'LOGGING', 'AND', 'MONITORING', 'SECURITY', 'MISCONFIGURATION', 'CROSS-SITE', 'SCRIPT', 'INCLUSION', '\(CSSI\)', 'CLICK', 'FRAUD', 'BROKEN', 'ACCESS', 'CONTROL', 'CLICKJACKING', 'HIDDEN', 'FORM', 'FIELDS', 'SHELLSHOCK', 'SERVER-SIDE', 'TEMPLATE', 'INJECTION', '\(SSTI\)', 'CODE', 'INJECTION', 'SESSION', 'FIXATION', 'SOAP', 'INJECTION', 'HTML', 'INJECTION', 'DOM-BASED', 'XSS', 'RFI', '\(REMOTE', 'FILE', 'INCLUSION\)', 'IDOR', '\(INSECURE', 'DIRECT', 'OBJECT', 'REFERENCE\)', 'DIRECTORY', 'TRAVERSAL', 'WEB', 'CACHE', 'POISONING', 'HIDDEN', 'FIELD', 'TAMPERING', 'CONNECTION', 'STRING', 'PARAMETER', 'POLLUTION', 'CRLF', 'INJECTION', 'XXE', '\(XML', 'EXTERNAL', 'ENTITY\)', 'INJECTION', 'SSRF', '\(SERVER-SIDE', 'REQUEST', 'FORGERY\)', 'XSS', '\(CROSS-SITE', 'SCRIPTING\)', 'RCE', '\(REMOTE', 'CODE', 'EXECUTION\)', 'UNRESTRICTED', 'FILE', 'UPLOAD', 'PASSWORD', 'CRACKING', 'SESSION', 'HIJACKING', 'BROKEN', 'AUTH', 'AND', 'SESSION', 'MANAGEMENT', 'Command', 'Injection', 'Xss', 'Dom', 'Xss', 'Sql', 'Injection', 'File', 'Inclusion', 'Directory', 'Traversal', 'Remote', 'File', 'Inclusion', 'Cross-Site', 'Request', 'Forgery', '\(Csrf\)', 'Unrestricted', 'File', 'Upload', 'Password', 'Cracking', 'Session', 'Hijacking', 'Broken', 'Auth', 'And', 'Session', 'Management', 'Remote', 'Code', 'Execution', 'Local', 'File', 'Inclusion', 'Server', 'Side', 'Request', 'Forgery', '\(Ssrf\)', 'Xml', 'External', 'Entity', '\(Xxe\)', 'Injection', 'Cross-Site', 'Script', 'Inclusion', '\(Xssi\)', 'Ldap', 'Injection', 'Xpath', 'Injection', 'Object', 'Injection', 'Cross-Domain', 'Scripting', 'Http', 'Response', 'Splitting', 'Buffer', 'Overflow', 'Insecure', 'Cryptographic', 'Storage', 'Insecure', 'Direct', 'Object', 'References', 'Insufficient', 'Logging', 'And', 'Monitoring', 'Security', 'Misconfiguration', 'Cross-Site', 'Script', 'Inclusion', '\(Cssi\)', 'Click', 'Fraud', 'Broken', 'Access', 'Control', 'Clickjacking', 'Hidden', 'Form', 'Fields', 'Shellshock', 'Server-Side', 'Template', 'Injection', '\(Ssti\)', 'Code', 'Injection', 'Session', 'Fixation', 'Soap', 'Injection', 'Html', 'Injection', 'Dom-Based', 'Xss', 'Rfi', '\(Remote', 'File', 'Inclusion\)', 'Idor', '\(Insecure', 'Direct', 'Object', 'Reference\)', 'Directory', 'Traversal', 'Web', 'Cache', 'Poisoning', 'Hidden', 'Field', 'Tampering', 'Connection', 'String', 'Parameter', 'Pollution', 'Crlf', 'Injection', 'Xxe', '\(Xml', 'External', 'Entity\)', 'Injection', 'Ssrf', '\(Server-Side', 'Request', 'Forgery\)', 'Xss', '\(Cross-Site', 'Scripting\)', 'Rce', '\(Remote', 'Code', 'Execution\)', 'Unrestricted', 'File', 'Upload', 'Password', 'Cracking', 'Session', 'Hijacking', 'Broken', 'Auth', 'And', 'Session', 'Management', 'command', 'injection', 'xss', 'dom', 'xss', 'sql', 'injection', 'file', 'inclusion', 'directory', 'traversal', 'remote', 'file', 'inclusion', 'cross-site', 'request', 'forgery', '\(csrf\)', 'unrestricted', 'file', 'upload', 'password', 'cracking', 'session', 'hijacking', 'broken', 'auth', 'and', 'session', 'management', 'remote', 'code', 'execution', 'local', 'file', 'inclusion', 'server', 'side', 'request', 'forgery', '\(ssrf\)', 'xml', 'external', 'entity', '\(xxe\)', 'injection', 'cross-site', 'script', 'inclusion', '\(xssi\)', 'ldap', 'injection', 'xpath', 'injection', 'object', 'injection', 'cross-domain', 'scripting', 'http', 'response', 'splitting', 'buffer', 'overflow', 'insecure', 'cryptographic', 'storage', 'insecure', 'direct', 'object', 'references', 'insufficient', 'logging', 'and', 'monitoring', 'security', 'misconfiguration', 'cross-site', 'script', 'inclusion', '\(cssi\)', 'click', 'fraud', 'broken', 'access', 'control', 'clickjacking', 'hidden', 'form', 'fields', 'shellshock', 'server-side', 'template', 'injection', '\(ssti\)', 'code', 'injection', 'session', 'fixation', 'soap', 'injection', 'html', 'injection', 'dom-based', 'xss', 'rfi', '\(remote', 'file', 'inclusion\)', 'idor', '\(insecure', 'direct', 'object', 'reference\)', 'directory', 'traversal', 'web', 'cache', 'poisoning', 'hidden', 'field', 'tampering', 'connection', 'string', 'parameter', 'pollution', 'crlf', 'injection', 'xxe', '\(xml', 'external', 'entity\)', 'injection', 'ssrf', '\(server-side', 'request', 'forgery\)', 'xss', '\(cross-site', 'scripting\)', 'rce', '\(remote', 'code', 'execution\)', 'unrestricted', 'file', 'upload', 'password', 'cracking', 'session', 'hijacking', 'broken', 'auth', 'and', 'session', 'management','path traversal','directory traversal','unauthorized access','access control','forceful browsing','privilege escalation','authorization bypass','insecure direct object reference','IDOR','access control matrix','clickjacking','UI redressing','UI redress attack','user interface redressing','user interface redress attack','UI overlay attack','overlay attack'
    );

    my $patterntoscanb = join('|', map { quotemeta } @patterntoscantodetectab);

    # Check if the response content contains the patterntoscan within div tags
    if ($status_code == 200 && $content =~ /($patterntoscanb)/i) {
        # print "[No Anomaly] [$timestamp] Vulnerability pattern detected within div tags in the response content\n";
        return 0;
    }

    # print "[Info] [$timestamp] No anomalies detected in anycase!\n";
    return 0;  # Default case: not an anomaly
}


sub v3_anomaly {
    my ($content, $status_code, $dom_elements_found) = @_;

    my @patterntoscantodetect = (
      'COMMAND', 'INJECTION', 'XSS', 'DOM', 'XSS', 'SQL', 'INJECTION', 'FILE', 'INCLUSION', 'DIRECTORY', 'TRAVERSAL', 'REMOTE', 'FILE', 'INCLUSION', 'CROSS-SITE', 'REQUEST', 'FORGERY', '\(CSRF\)', 'UNRESTRICTED', 'FILE', 'UPLOAD', 'PASSWORD', 'CRACKING', 'SESSION', 'HIJACKING', 'BROKEN', 'AUTH', 'AND', 'SESSION', 'MANAGEMENT', 'REMOTE', 'CODE', 'EXECUTION', 'LOCAL', 'FILE', 'INCLUSION', 'SERVER', 'SIDE', 'REQUEST', 'FORGERY', '\(SSRF\)', 'XML', 'EXTERNAL', 'ENTITY', '\(XXE\)', 'INJECTION', 'CROSS-SITE', 'SCRIPT', 'INCLUSION', '\(XSSI\)', 'LDAP', 'INJECTION', 'XPATH', 'INJECTION', 'OBJECT', 'INJECTION', 'CROSS-DOMAIN', 'SCRIPTING', 'HTTP', 'RESPONSE', 'SPLITTING', 'BUFFER', 'OVERFLOW', 'INSECURE', 'CRYPTOGRAPHIC', 'STORAGE', 'INSECURE', 'DIRECT', 'OBJECT', 'REFERENCES', 'INSUFFICIENT', 'LOGGING', 'AND', 'MONITORING', 'SECURITY', 'MISCONFIGURATION', 'CROSS-SITE', 'SCRIPT', 'INCLUSION', '\(CSSI\)', 'CLICK', 'FRAUD', 'BROKEN', 'ACCESS', 'CONTROL', 'CLICKJACKING', 'HIDDEN', 'FORM', 'FIELDS', 'SHELLSHOCK', 'SERVER-SIDE', 'TEMPLATE', 'INJECTION', '\(SSTI\)', 'CODE', 'INJECTION', 'SESSION', 'FIXATION', 'SOAP', 'INJECTION', 'HTML', 'INJECTION', 'DOM-BASED', 'XSS', 'RFI', '\(REMOTE', 'FILE', 'INCLUSION\)', 'IDOR', '\(INSECURE', 'DIRECT', 'OBJECT', 'REFERENCE\)', 'DIRECTORY', 'TRAVERSAL', 'WEB', 'CACHE', 'POISONING', 'HIDDEN', 'FIELD', 'TAMPERING', 'CONNECTION', 'STRING', 'PARAMETER', 'POLLUTION', 'CRLF', 'INJECTION', 'XXE', '\(XML', 'EXTERNAL', 'ENTITY\)', 'INJECTION', 'SSRF', '\(SERVER-SIDE', 'REQUEST', 'FORGERY\)', 'XSS', '\(CROSS-SITE', 'SCRIPTING\)', 'RCE', '\(REMOTE', 'CODE', 'EXECUTION\)', 'UNRESTRICTED', 'FILE', 'UPLOAD', 'PASSWORD', 'CRACKING', 'SESSION', 'HIJACKING', 'BROKEN', 'AUTH', 'AND', 'SESSION', 'MANAGEMENT', 'Command', 'Injection', 'Xss', 'Dom', 'Xss', 'Sql', 'Injection', 'File', 'Inclusion', 'Directory', 'Traversal', 'Remote', 'File', 'Inclusion', 'Cross-Site', 'Request', 'Forgery', '\(Csrf\)', 'Unrestricted', 'File', 'Upload', 'Password', 'Cracking', 'Session', 'Hijacking', 'Broken', 'Auth', 'And', 'Session', 'Management', 'Remote', 'Code', 'Execution', 'Local', 'File', 'Inclusion', 'Server', 'Side', 'Request', 'Forgery', '\(Ssrf\)', 'Xml', 'External', 'Entity', '\(Xxe\)', 'Injection', 'Cross-Site', 'Script', 'Inclusion', '\(Xssi\)', 'Ldap', 'Injection', 'Xpath', 'Injection', 'Object', 'Injection', 'Cross-Domain', 'Scripting', 'Http', 'Response', 'Splitting', 'Buffer', 'Overflow', 'Insecure', 'Cryptographic', 'Storage', 'Insecure', 'Direct', 'Object', 'References', 'Insufficient', 'Logging', 'And', 'Monitoring', 'Security', 'Misconfiguration', 'Cross-Site', 'Script', 'Inclusion', '\(Cssi\)', 'Click', 'Fraud', 'Broken', 'Access', 'Control', 'Clickjacking', 'Hidden', 'Form', 'Fields', 'Shellshock', 'Server-Side', 'Template', 'Injection', '\(Ssti\)', 'Code', 'Injection', 'Session', 'Fixation', 'Soap', 'Injection', 'Html', 'Injection', 'Dom-Based', 'Xss', 'Rfi', '\(Remote', 'File', 'Inclusion\)', 'Idor', '\(Insecure', 'Direct', 'Object', 'Reference\)', 'Directory', 'Traversal', 'Web', 'Cache', 'Poisoning', 'Hidden', 'Field', 'Tampering', 'Connection', 'String', 'Parameter', 'Pollution', 'Crlf', 'Injection', 'Xxe', '\(Xml', 'External', 'Entity\)', 'Injection', 'Ssrf', '\(Server-Side', 'Request', 'Forgery\)', 'Xss', '\(Cross-Site', 'Scripting\)', 'Rce', '\(Remote', 'Code', 'Execution\)', 'Unrestricted', 'File', 'Upload', 'Password', 'Cracking', 'Session', 'Hijacking', 'Broken', 'Auth', 'And', 'Session', 'Management', 'command', 'injection', 'xss', 'dom', 'xss', 'sql', 'injection', 'file', 'inclusion', 'directory', 'traversal', 'remote', 'file', 'inclusion', 'cross-site', 'request', 'forgery', '\(csrf\)', 'unrestricted', 'file', 'upload', 'password', 'cracking', 'session', 'hijacking', 'broken', 'auth', 'and', 'session', 'management', 'remote', 'code', 'execution', 'local', 'file', 'inclusion', 'server', 'side', 'request', 'forgery', '\(ssrf\)', 'xml', 'external', 'entity', '\(xxe\)', 'injection', 'cross-site', 'script', 'inclusion', '\(xssi\)', 'ldap', 'injection', 'xpath', 'injection', 'object', 'injection', 'cross-domain', 'scripting', 'http', 'response', 'splitting', 'buffer', 'overflow', 'insecure', 'cryptographic', 'storage', 'insecure', 'direct', 'object', 'references', 'insufficient', 'logging', 'and', 'monitoring', 'security', 'misconfiguration', 'cross-site', 'script', 'inclusion', '\(cssi\)', 'click', 'fraud', 'broken', 'access', 'control', 'clickjacking', 'hidden', 'form', 'fields', 'shellshock', 'server-side', 'template', 'injection', '\(ssti\)', 'code', 'injection', 'session', 'fixation', 'soap', 'injection', 'html', 'injection', 'dom-based', 'xss', 'rfi', '\(remote', 'file', 'inclusion\)', 'idor', '\(insecure', 'direct', 'object', 'reference\)', 'directory', 'traversal', 'web', 'cache', 'poisoning', 'hidden', 'field', 'tampering', 'connection', 'string', 'parameter', 'pollution', 'crlf', 'injection', 'xxe', '\(xml', 'external', 'entity\)', 'injection', 'ssrf', '\(server-side', 'request', 'forgery\)', 'xss', '\(cross-site', 'scripting\)', 'rce', '\(remote', 'code', 'execution\)', 'unrestricted', 'file', 'upload', 'password', 'cracking', 'session', 'hijacking', 'broken', 'auth', 'and', 'session', 'management','path traversal','directory traversal','unauthorized access','access control','forceful browsing','privilege escalation','authorization bypass','insecure direct object reference','IDOR','access control matrix','clickjacking','UI redressing','UI redress attack','user interface redressing','user interface redress attack','UI overlay attack','overlay attack','SQL Injection', 'Sql injection', 'sql injection','Command Injection', 'Command injection', 'command injection','XSS', 'Xss', 'xss','File Inclusion', 'File inclusion', 'file inclusion','Directory Traversal', 'Directory traversal', 'directory traversal','Remote File Inclusion', 'Remote file inclusion', 'remote file inclusion','Command Injection', 'Command injection', 'command injection','Cross-Site Request Forgery \(CSRF\)', 'Csrf', 'csrf','CSRF', 'Csrf', 'csrf','Unrestricted File Upload', 'Unrestricted file upload', 'unrestricted file upload','Password Cracking', 'Password cracking', 'password cracking','Session Hijacking', 'Session hijacking', 'session hijacking','Broken Auth and Session Management', 'Broken auth and session management', 'broken auth and session management','Remote Code Execution', 'Remote code execution', 'remote code execution','Local File Inclusion', 'Local file inclusion', 'local file inclusion','Server Side Request Forgery \(SSRF\)', 'Ssrf', 'ssrf','SSRF', 'Ssrf', 'ssrf','XML External Entity \(XXE\) Injection', 'Xxe injection', 'xxe injection','XXE', 'Xxe', 'xxe','Cross-Site Script Inclusion \(XSSI\)', 'Xssi', 'xssi','XXSI', 'Xxsi', 'xxsi','LDAP Injection', 'Ldap injection', 'ldap injection','XPath Injection', 'Xpath injection', 'xpath injection','Object Injection', 'Object injection', 'object injection','Cross-Domain Scripting', 'Cross-domain scripting', 'cross-domain scripting','HTTP Response Splitting', 'Http response splitting', 'http response splitting','Format String Attack', 'Format string attack', 'format string attack','Insecure Cryptographic Storage', 'Insecure cryptographic storage', 'insecure cryptographic storage','Insecure Direct Object References', 'Insecure direct object references', 'insecure direct object references','Insufficient Logging and Monitoring', 'Insufficient logging and monitoring', 'insufficient logging and monitoring','Security Misconfiguration', 'Security misconfiguration', 'security misconfiguration','Cross-Site Script Inclusion \(CSSI\)', 'Cssi', 'cssi','CSSI', 'Cssi', 'cssi','Click Fraud', 'Click fraud', 'click fraud','Broken Access Control', 'Broken access control', 'broken access control','Clickjacking', 'Clickjacking', 'clickjacking','Hidden Form Fields', 'Hidden form fields', 'hidden form fields','Shellshock', 'Shellshock', 'shellshock','Server-Side Template Injection \(SSTI\)', 'Ssti', 'ssti','SSTI', 'Ssti', 'ssti','Code Injection', 'Code injection', 'code injection','Session Fixation', 'Session fixation', 'session fixation','SOAP Injection', 'Soap injection', 'soap injection','HTML Injection', 'Html injection', 'html injection','DOM-based XSS', 'Dom-based xss', 'dom-based xss','RFI \(Remote File Inclusion\)', 'Rfi', 'rfi','RFI', 'Rfi', 'rfi','IDOR \(Insecure Direct Object Reference\)', 'Idor', 'idor','IDOR', 'Idor', 'idor','Directory Traversal', 'Directory traversal', 'directory traversal','Web Cache Poisoning', 'Web cache poisoning', 'web cache poisoning','Hidden Field Tampering', 'Hidden field tampering', 'hidden field tampering','Connection String Parameter Pollution', 'Connection string parameter pollution', 'connection string parameter pollution','CRLF Injection', 'Crlf injection', 'crlf injection','XML External Entity', 'Xml external entity', 'xml external entity','RCE \(Remote Code Execution\)', 'Rce', 'rce','RCE', 'Rce', 'rce','Unrestricted File Upload', 'Unrestricted file upload', 'unrestricted file upload','Password Cracking', 'Password cracking', 'password cracking','Session Hijacking', 'Session hijacking', 'session hijacking','Broken Auth and Session Management', 'Broken auth and session management', 'broken auth and session management'
    );

    my $patterntoscan = join('|', map { quotemeta } @patterntoscantodetect);

    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);

    # Check if the response content contains the patterntoscan within div tags
    if ($status_code == 200 && $dom_elements_found && $content !~ /<(?:body|html)[^>]*($patterntoscan)/i) {
        # print "[No Anomaly] [$timestamp] Vulnerability pattern detected within div tags in the response content\n";
        return 0;
    }

    # print "[Info] [$timestamp] No anomalies detected in any case!\n";
    return 0;  # Default case: not an anomaly
}



sub v4_anomaly {
    my ($content, $status_code, $timestamp) = @_;

    my @patterntoscantodetectb = (
      'COMMAND', 'INJECTION', 'XSS', 'DOM', 'XSS', 'SQL', 'INJECTION', 'FILE', 'INCLUSION', 'DIRECTORY', 'TRAVERSAL', 'REMOTE', 'FILE', 'INCLUSION', 'CROSS-SITE', 'REQUEST', 'FORGERY', '\(CSRF\)', 'UNRESTRICTED', 'FILE', 'UPLOAD', 'PASSWORD', 'CRACKING', 'SESSION', 'HIJACKING', 'BROKEN', 'AUTH', 'AND', 'SESSION', 'MANAGEMENT', 'REMOTE', 'CODE', 'EXECUTION', 'LOCAL', 'FILE', 'INCLUSION', 'SERVER', 'SIDE', 'REQUEST', 'FORGERY', '\(SSRF\)', 'XML', 'EXTERNAL', 'ENTITY', '\(XXE\)', 'INJECTION', 'CROSS-SITE', 'SCRIPT', 'INCLUSION', '\(XSSI\)', 'LDAP', 'INJECTION', 'XPATH', 'INJECTION', 'OBJECT', 'INJECTION', 'CROSS-DOMAIN', 'SCRIPTING', 'HTTP', 'RESPONSE', 'SPLITTING', 'BUFFER', 'OVERFLOW', 'INSECURE', 'CRYPTOGRAPHIC', 'STORAGE', 'INSECURE', 'DIRECT', 'OBJECT', 'REFERENCES', 'INSUFFICIENT', 'LOGGING', 'AND', 'MONITORING', 'SECURITY', 'MISCONFIGURATION', 'CROSS-SITE', 'SCRIPT', 'INCLUSION', '\(CSSI\)', 'CLICK', 'FRAUD', 'BROKEN', 'ACCESS', 'CONTROL', 'CLICKJACKING', 'HIDDEN', 'FORM', 'FIELDS', 'SHELLSHOCK', 'SERVER-SIDE', 'TEMPLATE', 'INJECTION', '\(SSTI\)', 'CODE', 'INJECTION', 'SESSION', 'FIXATION', 'SOAP', 'INJECTION', 'HTML', 'INJECTION', 'DOM-BASED', 'XSS', 'RFI', '\(REMOTE', 'FILE', 'INCLUSION\)', 'IDOR', '\(INSECURE', 'DIRECT', 'OBJECT', 'REFERENCE\)', 'DIRECTORY', 'TRAVERSAL', 'WEB', 'CACHE', 'POISONING', 'HIDDEN', 'FIELD', 'TAMPERING', 'CONNECTION', 'STRING', 'PARAMETER', 'POLLUTION', 'CRLF', 'INJECTION', 'XXE', '\(XML', 'EXTERNAL', 'ENTITY\)', 'INJECTION', 'SSRF', '\(SERVER-SIDE', 'REQUEST', 'FORGERY\)', 'XSS', '\(CROSS-SITE', 'SCRIPTING\)', 'RCE', '\(REMOTE', 'CODE', 'EXECUTION\)', 'UNRESTRICTED', 'FILE', 'UPLOAD', 'PASSWORD', 'CRACKING', 'SESSION', 'HIJACKING', 'BROKEN', 'AUTH', 'AND', 'SESSION', 'MANAGEMENT', 'Command', 'Injection', 'Xss', 'Dom', 'Xss', 'Sql', 'Injection', 'File', 'Inclusion', 'Directory', 'Traversal', 'Remote', 'File', 'Inclusion', 'Cross-Site', 'Request', 'Forgery', '\(Csrf\)', 'Unrestricted', 'File', 'Upload', 'Password', 'Cracking', 'Session', 'Hijacking', 'Broken', 'Auth', 'And', 'Session', 'Management', 'Remote', 'Code', 'Execution', 'Local', 'File', 'Inclusion', 'Server', 'Side', 'Request', 'Forgery', '\(Ssrf\)', 'Xml', 'External', 'Entity', '\(Xxe\)', 'Injection', 'Cross-Site', 'Script', 'Inclusion', '\(Xssi\)', 'Ldap', 'Injection', 'Xpath', 'Injection', 'Object', 'Injection', 'Cross-Domain', 'Scripting', 'Http', 'Response', 'Splitting', 'Buffer', 'Overflow', 'Insecure', 'Cryptographic', 'Storage', 'Insecure', 'Direct', 'Object', 'References', 'Insufficient', 'Logging', 'And', 'Monitoring', 'Security', 'Misconfiguration', 'Cross-Site', 'Script', 'Inclusion', '\(Cssi\)', 'Click', 'Fraud', 'Broken', 'Access', 'Control', 'Clickjacking', 'Hidden', 'Form', 'Fields', 'Shellshock', 'Server-Side', 'Template', 'Injection', '\(Ssti\)', 'Code', 'Injection', 'Session', 'Fixation', 'Soap', 'Injection', 'Html', 'Injection', 'Dom-Based', 'Xss', 'Rfi', '\(Remote', 'File', 'Inclusion\)', 'Idor', '\(Insecure', 'Direct', 'Object', 'Reference\)', 'Directory', 'Traversal', 'Web', 'Cache', 'Poisoning', 'Hidden', 'Field', 'Tampering', 'Connection', 'String', 'Parameter', 'Pollution', 'Crlf', 'Injection', 'Xxe', '\(Xml', 'External', 'Entity\)', 'Injection', 'Ssrf', '\(Server-Side', 'Request', 'Forgery\)', 'Xss', '\(Cross-Site', 'Scripting\)', 'Rce', '\(Remote', 'Code', 'Execution\)', 'Unrestricted', 'File', 'Upload', 'Password', 'Cracking', 'Session', 'Hijacking', 'Broken', 'Auth', 'And', 'Session', 'Management', 'command', 'injection', 'xss', 'dom', 'xss', 'sql', 'injection', 'file', 'inclusion', 'directory', 'traversal', 'remote', 'file', 'inclusion', 'cross-site', 'request', 'forgery', '\(csrf\)', 'unrestricted', 'file', 'upload', 'password', 'cracking', 'session', 'hijacking', 'broken', 'auth', 'and', 'session', 'management', 'remote', 'code', 'execution', 'local', 'file', 'inclusion', 'server', 'side', 'request', 'forgery', '\(ssrf\)', 'xml', 'external', 'entity', '\(xxe\)', 'injection', 'cross-site', 'script', 'inclusion', '\(xssi\)', 'ldap', 'injection', 'xpath', 'injection', 'object', 'injection', 'cross-domain', 'scripting', 'http', 'response', 'splitting', 'buffer', 'overflow', 'insecure', 'cryptographic', 'storage', 'insecure', 'direct', 'object', 'references', 'insufficient', 'logging', 'and', 'monitoring', 'security', 'misconfiguration', 'cross-site', 'script', 'inclusion', '\(cssi\)', 'click', 'fraud', 'broken', 'access', 'control', 'clickjacking', 'hidden', 'form', 'fields', 'shellshock', 'server-side', 'template', 'injection', '\(ssti\)', 'code', 'injection', 'session', 'fixation', 'soap', 'injection', 'html', 'injection', 'dom-based', 'xss', 'rfi', '\(remote', 'file', 'inclusion\)', 'idor', '\(insecure', 'direct', 'object', 'reference\)', 'directory', 'traversal', 'web', 'cache', 'poisoning', 'hidden', 'field', 'tampering', 'connection', 'string', 'parameter', 'pollution', 'crlf', 'injection', 'xxe', '\(xml', 'external', 'entity\)', 'injection', 'ssrf', '\(server-side', 'request', 'forgery\)', 'xss', '\(cross-site', 'scripting\)', 'rce', '\(remote', 'code', 'execution\)', 'unrestricted', 'file', 'upload', 'password', 'cracking', 'session', 'hijacking', 'broken', 'auth', 'and', 'session', 'management','path traversal','directory traversal','unauthorized access','access control','forceful browsing','privilege escalation','authorization bypass','insecure direct object reference','IDOR','access control matrix','clickjacking','UI redressing','UI redress attack','user interface redressing','user interface redress attack','UI overlay attack','overlay attack','SQL Injection', 'Sql injection', 'sql injection','Command Injection', 'Command injection', 'command injection','XSS', 'Xss', 'xss','File Inclusion', 'File inclusion', 'file inclusion','Directory Traversal', 'Directory traversal', 'directory traversal','Remote File Inclusion', 'Remote file inclusion', 'remote file inclusion','Command Injection', 'Command injection', 'command injection','Cross-Site Request Forgery \(CSRF\)', 'Csrf', 'csrf','CSRF', 'Csrf', 'csrf','Unrestricted File Upload', 'Unrestricted file upload', 'unrestricted file upload','Password Cracking', 'Password cracking', 'password cracking','Session Hijacking', 'Session hijacking', 'session hijacking','Broken Auth and Session Management', 'Broken auth and session management', 'broken auth and session management','Remote Code Execution', 'Remote code execution', 'remote code execution','Local File Inclusion', 'Local file inclusion', 'local file inclusion','Server Side Request Forgery \(SSRF\)', 'Ssrf', 'ssrf','SSRF', 'Ssrf', 'ssrf','XML External Entity \(XXE\) Injection', 'Xxe injection', 'xxe injection','XXE', 'Xxe', 'xxe','Cross-Site Script Inclusion \(XSSI\)', 'Xssi', 'xssi','XXSI', 'Xxsi', 'xxsi','LDAP Injection', 'Ldap injection', 'ldap injection','XPath Injection', 'Xpath injection', 'xpath injection','Object Injection', 'Object injection', 'object injection','Cross-Domain Scripting', 'Cross-domain scripting', 'cross-domain scripting','HTTP Response Splitting', 'Http response splitting', 'http response splitting','Format String Attack', 'Format string attack', 'format string attack','Insecure Cryptographic Storage', 'Insecure cryptographic storage', 'insecure cryptographic storage','Insecure Direct Object References', 'Insecure direct object references', 'insecure direct object references','Insufficient Logging and Monitoring', 'Insufficient logging and monitoring', 'insufficient logging and monitoring','Security Misconfiguration', 'Security misconfiguration', 'security misconfiguration','Cross-Site Script Inclusion \(CSSI\)', 'Cssi', 'cssi','CSSI', 'Cssi', 'cssi','Click Fraud', 'Click fraud', 'click fraud','Broken Access Control', 'Broken access control', 'broken access control','Clickjacking', 'Clickjacking', 'clickjacking','Hidden Form Fields', 'Hidden form fields', 'hidden form fields','Shellshock', 'Shellshock', 'shellshock','Server-Side Template Injection \(SSTI\)', 'Ssti', 'ssti','SSTI', 'Ssti', 'ssti','Code Injection', 'Code injection', 'code injection','Session Fixation', 'Session fixation', 'session fixation','SOAP Injection', 'Soap injection', 'soap injection','HTML Injection', 'Html injection', 'html injection','DOM-based XSS', 'Dom-based xss', 'dom-based xss','RFI \(Remote File Inclusion\)', 'Rfi', 'rfi','RFI', 'Rfi', 'rfi','IDOR \(Insecure Direct Object Reference\)', 'Idor', 'idor','IDOR', 'Idor', 'idor','Directory Traversal', 'Directory traversal', 'directory traversal','Web Cache Poisoning', 'Web cache poisoning', 'web cache poisoning','Hidden Field Tampering', 'Hidden field tampering', 'hidden field tampering','Connection String Parameter Pollution', 'Connection string parameter pollution', 'connection string parameter pollution','CRLF Injection', 'Crlf injection', 'crlf injection','XML External Entity', 'Xml external entity', 'xml external entity','RCE \(Remote Code Execution\)', 'Rce', 'rce','RCE', 'Rce', 'rce','Unrestricted File Upload', 'Unrestricted file upload', 'unrestricted file upload','Password Cracking', 'Password cracking', 'password cracking','Session Hijacking', 'Session hijacking', 'session hijacking','Broken Auth and Session Management', 'Broken auth and session management', 'broken auth and session management'
    );

    my $patterntoscana = join('|', map { quotemeta } @patterntoscantodetectb);

    # Check if the response content contains the patterntoscan within div tags
    if ($status_code == 200 && $content =~ /<(?:body|html)[^>]*($patterntoscana)/i) {
        # print "[No Anomaly] [$timestamp] Vulnerability pattern detected within div tags in the response content\n";
        return 0;
    }

    # print "[Info] [$timestamp] No anomalies detected in any case!\n";
    return 0;  # Default case: not an anomaly
}

# Function to parse command-line arguments
sub parse_arguments {
    my $url;
    GetOptions("url=s" => \$url) or die "[Error] [$timestamp] Usage: $0 --url <URL>\n";
    return $url;
}

# Function to log vulnerabilities
sub log_vulnerability {
    my ($vulnerabilities_log, $vulnerability_name, $url) = @_;
    open(my $fh, '>>', $vulnerabilities_log) or die "[Error] [$timestamp] Cannot open $vulnerabilities_log: $!";
    print $fh "[$timestamp] [$vulnerability_name] $url\n";
    close($fh);
}

# Function to log responses
sub log_response {
    my ($responses_log, $url, $response) = @_;
    open(my $fh, '>>', $responses_log) or die "[Error] [$timestamp] Cannot open $responses_log: $!";
    
    # Encode the content before printing it
    my $encoded_content = encode('UTF-8', $response->as_string);

    print $fh "[$timestamp] [$url]\n";
    print $fh $encoded_content . "\n\n";
    close($fh);
}
use File::Path qw(make_path);

# Function to create the output folder
sub create_output_folder {
    my $current_date   = strftime("%Y-%m-%d_%H-%M-%S", localtime);
    my $top_level      = OUTPUT_FOLDER;               # e.g., 'output'
    my $output_folder  = "$top_level/$current_date";  # e.g., 'output/2025-01-27_12-34-56'

    # Ensure the top-level directory exists
    unless (-d $top_level) {
        make_path($top_level) 
            or die "[Error] Could not create directory '$top_level': $!";
    }

    # Create the timestamped subdirectory if it doesn't exist
    unless (-d $output_folder) {
        mkdir $output_folder 
            or die "[Error] Could not create directory '$output_folder': $!";
    }

    return $output_folder;
}
# [SNIPPET] Enhanced Global Exploit/Success/Error Pattern
# This pattern aims to capture common error messages, 
# success indicators, and potential "OWASP Top 10" or CEH references.
# Define the global exploit pattern
my $exploit_pattern = qr{
    \b
    (
        # Generic "exploit worked" messages
        pwned |
        error |
        Error |
        # Typical SQL injection error indicators
        syntax\s+error\s+in\s+sql |
        you\s+have\s+an\s+error\s+in\s+your\s+sql\s+syntax |
        warning:\s+mysql_.* |
        unknown\s+column\s+.*\s+in\s+field\s+list |
        microsoft\s+ole\s+db\s+provider\s+for\s+sql\s+server\s+error |
        unclosed\s+quotation\s+mark\s+after\s+the\s+character\s+string
        
        # Command Injection and Shell output hints
        uid\s*=\s*\d+\(.*?\)\s+gid\s*=\s*\d+\(.*?\) |
        root:x:0:0: |
        server\s+executed\s+your\s+command
        
        # XSS or script injection indicators
        xss\s+test\s+triggered |
        <script>alert\(\s*["']xss["']\s*\)|alert\("xss"\)
        
        # Common Attack Patterns referencing OWASP or CEH
        owasp\stop\s+10 |
        ceh\s+test\s+payload
        
        # Remote File Inclusion (RFI) success indicator
        file\s+has\s+been\s+included\s+remotely
        
        # Local File Inclusion (LFI) success indicator
        etc/passwd
        
        # Extra patterns you might want
        command\sinjection\stest |
        server\stemplate\sinjection
        
        # Catch-all for anything else you want
        infiltration\s+complete
    )
    \b
}ix;

# ------------------------------------------------------------------
# Function to test vulnerabilities and log them (FIXED VERSION)
# ------------------------------------------------------------------
sub test_vulnerability {
    my ($ua, $url, $vulnerability_name, $pattern,
        $vulnerabilities_log, $responses_log, $verbose,
        $payload
    ) = @_;

    my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);

    # Make an HTTP GET request
    my $response = $ua->get($url);

    # Declare $status_code in the same scope so we can pass it to anomaly checks
    my $status_code = $response->code;

    if ($response->is_success) {
        # 1) Get the response body
        my $content = $response->decoded_content;

        # 2) Immediately check if content matches the global $exploit_pattern
        if ($content =~ /$exploit_pattern/) {
            handle_vulnerability("Exploit/OWASP Pattern Match",
                                 $url, $vulnerabilities_log, $payload);
        }

        # 3) Continue with the rest of your existing checks
        if ($content =~ /$pattern/i
            || is_anomaly_v1($content, $status_code, $pattern, 0)
            || is_anomaly_v2($content, $status_code, $pattern)
            || v3_anomaly($content, $status_code, 0)
            || v4_anomaly($content, $status_code, $timestamp)
        ) {
            handle_vulnerability($vulnerability_name,
                                 $url, $vulnerabilities_log, $payload);
        }
        elsif ($verbose) {
            print "[Safe Link] [$timestamp] It appears to be safe ...\n";
        }

        # Log the response content (unchanged)
        open(my $fh_resp, '>>', $responses_log)
            or die "[Error] [$timestamp] Cannot open $responses_log: $!";
        print $fh_resp "[$timestamp] Response: $url\n$content\n\n";
        close($fh_resp);

    }
    else {
        # Error/Non-200 handling (unchanged)
        print "\n\n[Vulnerability] [$timestamp] HTTP response code anomaly ",
              "detected for $url: HTTP $status_code for Vuln: $vulnerability_name\n\n";

        open(my $fh_resp, '>>', $responses_log)
            or die "[Error] [$timestamp] Cannot open $responses_log: $!";
        print $fh_resp "[$timestamp] $url => HTTP $status_code\n";
        close($fh_resp);
    }
}


# Function to check if a URL belongs to the same domain as the base URL
sub is_same_domain {
    my ($url, $base_url) = @_;
    my $uri = URI->new($url)->canonical;
    my $base_uri = URI->new($base_url)->canonical;

    return $uri->host eq $base_uri->host;
}

# Function to crawl and test vulnerabilities
sub crawl_and_test {
    my ($ua, $url, $options) = @_;
    my $vulnerabilities_log = $options->{vulnerabilities_log};
    my $responses_log = $options->{responses_log};
    my $verbose = $options->{verbose};
    my $tested_links = $options->{tested_links};
    my $vulnerabilities = $options->{vulnerabilities};

    # Check if the URL has been visited already to prevent revisiting
    return if $tested_links->{$url};

    # Mark the URL as visited
    $tested_links->{$url} = 1;

    # Make an HTTP GET request to the URL
    my $response = $ua->get($url);

    if ($response->is_success) {
        $content = $response->decoded_content;

    if ($content =~ /$exploit_pattern/) {
        handle_vulnerability(
        "Exploit/OWASP Pattern Match",
        $url,
        $vulnerabilities_log,
        "[N/A]"    # <-- Replace $payload with "[N/A]" or a similar placeholder
    );
    }
        # Usage:
        if (!is_same_domain($url, $base_url)) {
            print "[Info] [$timestamp] Skipping external URL: $url\n";
            return;
        }


# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Command_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;

    # Skip if the line is empty or just whitespace
    next if $payload =~ /^\s*$/;

    test_vulnerability(
        $ua,
        $url,
        "Command Injection",
        qr/\Q$payload\E/i,
        $vulnerabilities_log,
        $responses_log,
        $verbose,
        $payload
    );
}
# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SQL_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "SQL Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XSS_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "XSS Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'File_Inclusion.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "File Inclusion", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Directory_Traversal.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Directory Traversal", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Remote_File_Inclusion.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Remote File Inclusion", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'CSRF.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Cross-Site Request Forgery (CSRF)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Unrestricted_File_Upload.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Unrestricted File Upload", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Password_Cracking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Password Cracking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Session_Hijacking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Session Hijacking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Broken_Auth_and_Session_Management.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Broken Auth and Session Management", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Remote_Code_Execution.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Remote Code Execution", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Local_File_Inclusion.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Local File Inclusion", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SSRF.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Server Side Request Forgery (SSRF)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XXE.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "XML External Entity (XXE) Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'LDAP_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "LDAP Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XPath_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "XPath Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Object_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Object Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Cross_Domain_Scripting.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Cross-Domain Scripting", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'HTTP_Response_Splitting.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "HTTP Response Splitting", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Buffer_Overflow.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Buffer Overflow", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Format_String_Attack.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Format String Attack", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Insecure_Cryptographic_Storage.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Insecure Cryptographic Storage", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Insecure_Direct_Object_References.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Insecure Direct Object References", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Insufficient_Logging_and_Monitoring.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Insufficient Logging and Monitoring", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Security_Misconfiguration.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Security Misconfiguration", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Click_Fraud.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Click Fraud", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Security_Misconfiguration.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Security Misconfiguration", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Broken_Access_Control.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Broken Access Control", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Clickjacking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Clickjacking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Hidden_Form_Fields.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Hidden Form Fields", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Shellshock.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Shellshock", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Hidden_Form_Fields.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Hidden Form Fields", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SSTI.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Server-Side Template Injection (SSTI)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Session_Fixation.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Session Fixation", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SOAP_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "SOAP Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'HTML_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "HTML Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'DOM_based_XSS.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "DOM-based XSS", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'RFI.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "RFI (Remote File Inclusion)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'IDOR.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "IDOR (Insecure Direct Object Reference)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Directory_Traversal.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Directory Traversal", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Web_Cache_Poisoning.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Web Cache Poisoning", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Hidden_Field_Tampering.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Hidden Field Tampering", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Connection_String_Parameter_Pollution.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Connection String Parameter Pollution", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'CRLF_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "CRLF Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XXE_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "XXE (XML External Entity) Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SSRF.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "SSRF (Server-Side Request Forgery)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'RCE.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "RCE (Remote Code Execution)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Unrestricted_File_Upload.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Unrestricted File Upload", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Password_Cracking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Password Cracking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Session_Hijacking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Session Hijacking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Broken_Auth_and_Session_Management.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $url, "Broken Auth and Session Management", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;

            }

        # Test DOM elements
        my $parser = parse_html($content);
        my @dom_elements = $parser->find('div', 'a', 'img', 'form', 'script', 'applet'); # Add other elements as needed

        if (@dom_elements) {
            my $timestamp = strftime("%Y-%m-%d %H:%M:%S", localtime);
            print "[Elements Detected] [$timestamp] DOM elements found on $url\n\n";

            foreach my $element (@dom_elements) {
                my $element_type = $element->tag;

                # Display or log information about the DOM element
                print "[Dom Detected] [$timestamp] [Element Testing] : $element_type for various test cases\n";

                if ($element->tag eq 'form') {
                    print "[Dom Detected] [$timestamp] [Element Testing] : $element_type for various test cases\n";
                    # Test for specific vulnerabilities with enhanced regex patterns
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Command_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Command Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SQL_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "SQL Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XSS_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "XSS Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'File_Inclusion.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "File Inclusion", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Directory_Traversal.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Directory Traversal", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Remote_File_Inclusion.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Remote File Inclusion", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'CSRF.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Cross-Site Request Forgery (CSRF)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Unrestricted_File_Upload.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Unrestricted File Upload", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Password_Cracking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Password Cracking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Session_Hijacking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Session Hijacking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Broken_Auth_and_Session_Management.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Broken Auth and Session Management", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Remote_Code_Execution.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Remote Code Execution", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Local_File_Inclusion.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Local File Inclusion", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SSRF.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Server Side Request Forgery (SSRF)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XXE.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "XML External Entity (XXE) Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'LDAP_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "LDAP Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XPath_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "XPath Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Object_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Object Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Cross_Domain_Scripting.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Cross-Domain Scripting", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'HTTP_Response_Splitting.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "HTTP Response Splitting", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Buffer_Overflow.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Buffer Overflow", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Format_String_Attack.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Format String Attack", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Insecure_Cryptographic_Storage.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Insecure Cryptographic Storage", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Insecure_Direct_Object_References.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Insecure Direct Object References", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Insufficient_Logging_and_Monitoring.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Insufficient Logging and Monitoring", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Security_Misconfiguration.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Security Misconfiguration", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Click_Fraud.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Click Fraud", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Security_Misconfiguration.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Security Misconfiguration", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Broken_Access_Control.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Broken Access Control", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Clickjacking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Clickjacking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Hidden_Form_Fields.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Hidden Form Fields", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Shellshock.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Shellshock", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Hidden_Form_Fields.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Hidden Form Fields", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SSTI.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Server-Side Template Injection (SSTI)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Session_Fixation.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Session Fixation", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SOAP_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "SOAP Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'HTML_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "HTML Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'DOM_based_XSS.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "DOM-based XSS", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'RFI.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "RFI (Remote File Inclusion)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'IDOR.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "IDOR (Insecure Direct Object Reference)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Directory_Traversal.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Directory Traversal", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Web_Cache_Poisoning.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Web Cache Poisoning", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Hidden_Field_Tampering.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Hidden Field Tampering", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Connection_String_Parameter_Pollution.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Connection String Parameter Pollution", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'CRLF_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "CRLF Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XXE_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "XXE (XML External Entity) Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SSRF.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "SSRF (Server-Side Request Forgery)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'RCE.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "RCE (Remote Code Execution)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Unrestricted_File_Upload.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Unrestricted File Upload", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Password_Cracking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Password Cracking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Session_Hijacking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Session Hijacking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Broken_Auth_and_Session_Management.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Broken Auth and Session Management", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
                }
                # Check if the DOM element contains JavaScript code
                if ($element->tag eq 'script') {
                    # Test for specific vulnerabilities with enhanced regex patterns
                print "[Dom Detected] [$timestamp] [Element Testing] : $element_type for various test cases\n";
                    # Test for specific vulnerabilities with enhanced regex patterns
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Command_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Command Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SQL_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "SQL Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XSS_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "XSS Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'File_Inclusion.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "File Inclusion", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Directory_Traversal.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Directory Traversal", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Remote_File_Inclusion.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Remote File Inclusion", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'CSRF.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Cross-Site Request Forgery (CSRF)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Unrestricted_File_Upload.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Unrestricted File Upload", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Password_Cracking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Password Cracking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Session_Hijacking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Session Hijacking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Broken_Auth_and_Session_Management.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Broken Auth and Session Management", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Remote_Code_Execution.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Remote Code Execution", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Local_File_Inclusion.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Local File Inclusion", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SSRF.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Server Side Request Forgery (SSRF)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XXE.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "XML External Entity (XXE) Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'LDAP_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "LDAP Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XPath_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "XPath Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Object_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Object Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Cross_Domain_Scripting.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Cross-Domain Scripting", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'HTTP_Response_Splitting.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "HTTP Response Splitting", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Buffer_Overflow.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Buffer Overflow", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Format_String_Attack.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Format String Attack", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Insecure_Cryptographic_Storage.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Insecure Cryptographic Storage", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Insecure_Direct_Object_References.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Insecure Direct Object References", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Insufficient_Logging_and_Monitoring.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Insufficient Logging and Monitoring", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Security_Misconfiguration.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Security Misconfiguration", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Click_Fraud.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Click Fraud", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Security_Misconfiguration.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Security Misconfiguration", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Broken_Access_Control.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Broken Access Control", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Clickjacking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Clickjacking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Hidden_Form_Fields.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Hidden Form Fields", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Shellshock.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Shellshock", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Hidden_Form_Fields.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Hidden Form Fields", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SSTI.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Server-Side Template Injection (SSTI)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Session_Fixation.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Session Fixation", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SOAP_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "SOAP Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'HTML_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "HTML Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'DOM_based_XSS.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "DOM-based XSS", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'RFI.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "RFI (Remote File Inclusion)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'IDOR.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "IDOR (Insecure Direct Object Reference)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Directory_Traversal.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Directory Traversal", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Web_Cache_Poisoning.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Web Cache Poisoning", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Hidden_Field_Tampering.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Hidden Field Tampering", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Connection_String_Parameter_Pollution.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Connection String Parameter Pollution", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'CRLF_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "CRLF Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XXE_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "XXE (XML External Entity) Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SSRF.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "SSRF (Server-Side Request Forgery)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'RCE.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "RCE (Remote Code Execution)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Unrestricted_File_Upload.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Unrestricted File Upload", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Password_Cracking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Password Cracking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Session_Hijacking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Session Hijacking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Broken_Auth_and_Session_Management.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Broken Auth and Session Management", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
                }
                # Check if the DOM element contains an applet
                if ($element->tag eq 'applet') {
                    # Test for specific vulnerabilities with enhanced regex patterns
                print "[Dom Detected] [$timestamp] [Element Testing] : $element_type for various test cases\n";
                    # Test for specific vulnerabilities with enhanced regex patterns
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Command_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Command Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SQL_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "SQL Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XSS_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "XSS Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'File_Inclusion.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "File Inclusion", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Directory_Traversal.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Directory Traversal", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Remote_File_Inclusion.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Remote File Inclusion", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'CSRF.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Cross-Site Request Forgery (CSRF)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Unrestricted_File_Upload.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Unrestricted File Upload", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Password_Cracking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Password Cracking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Session_Hijacking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Session Hijacking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Broken_Auth_and_Session_Management.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Broken Auth and Session Management", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Remote_Code_Execution.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Remote Code Execution", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Local_File_Inclusion.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Local File Inclusion", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SSRF.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Server Side Request Forgery (SSRF)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XXE.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "XML External Entity (XXE) Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'LDAP_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "LDAP Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XPath_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "XPath Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Object_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Object Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Cross_Domain_Scripting.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Cross-Domain Scripting", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'HTTP_Response_Splitting.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "HTTP Response Splitting", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Buffer_Overflow.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Buffer Overflow", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Format_String_Attack.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Format String Attack", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Insecure_Cryptographic_Storage.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Insecure Cryptographic Storage", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Insecure_Direct_Object_References.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Insecure Direct Object References", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Insufficient_Logging_and_Monitoring.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Insufficient Logging and Monitoring", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Security_Misconfiguration.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Security Misconfiguration", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Click_Fraud.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Click Fraud", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Security_Misconfiguration.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Security Misconfiguration", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Broken_Access_Control.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Broken Access Control", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Clickjacking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Clickjacking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Hidden_Form_Fields.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Hidden Form Fields", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Shellshock.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Shellshock", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Hidden_Form_Fields.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Hidden Form Fields", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SSTI.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Server-Side Template Injection (SSTI)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Session_Fixation.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Session Fixation", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SOAP_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "SOAP Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'HTML_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "HTML Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'DOM_based_XSS.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "DOM-based XSS", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'RFI.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "RFI (Remote File Inclusion)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'IDOR.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "IDOR (Insecure Direct Object Reference)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Directory_Traversal.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Directory Traversal", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Web_Cache_Poisoning.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Web Cache Poisoning", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Hidden_Field_Tampering.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Hidden Field Tampering", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Connection_String_Parameter_Pollution.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Connection String Parameter Pollution", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'CRLF_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "CRLF Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'XXE_Injection.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "XXE (XML External Entity) Injection", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'SSRF.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "SSRF (Server-Side Request Forgery)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'RCE.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "RCE (Remote Code Execution)", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Unrestricted_File_Upload.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Unrestricted File Upload", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Password_Cracking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Password Cracking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Session_Hijacking.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Session Hijacking", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
    }

{
# Open the file containing payloads for another vulnerability type
open my $payloads_fh, '<', 'Broken_Auth_and_Session_Management.txt' or die "Could not open payloads file: $!";

# Iterate over the payloads and test each one
while (my $payload = <$payloads_fh>) {
    chomp $payload;  # Remove newline character
    test_vulnerability($ua, $element->as_HTML, "Broken Auth and Session Management", qr/\Q$payload\E/i, $vulnerabilities_log, $responses_log, $verbose);
}

# Close the payloads file
close $payloads_fh;
       }
        }

        # Extract links from the content
        my $links = extract_links($url, $content);

        # Log discovered links
        log_links(VULNERABILITIES_LOG, $url, $links);

        if (ref $links eq 'ARRAY') {
            foreach my $link (@$links) {
                # Process each link
                crawl_and_test($ua, $link, $options);
            }
        } else {
            print "[Warning] [$timestamp] Links is not an array reference: $url\n";
        }
    }
}

# Function to create an HTML report
sub create_html_report {
    my ($output_folder, $vulnerabilities_log, $responses_log) = @_;
    my $report_file = "$output_folder/report.html";

    open(my $fh, '>:encoding(UTF-8)', $report_file) or die "[Error] [$timestamp] Cannot create HTML report: $!";
    
    print $fh "<html>\n<head>\n<title>Vulnerability Report</title>\n</head>\n<body>\n";
    print $fh "<h1>Vulnerability Report</h1>\n";
    print $fh "<h2>Vulnerabilities Found</h2>\n";

    if (-e $vulnerabilities_log) {
        open(my $log_fh, '<', $vulnerabilities_log) or die "[Error] [$timestamp] Cannot open vulnerabilities log file: $!";
        while (<$log_fh>) {
            print $fh "<p>$_</p>\n";
        }
        close($log_fh);
    } else {
        print $fh "<p>No vulnerabilities found.</p>\n";
    }

    print $fh "<h2>HTTP Responses</h2>\n";
    print $fh "<pre>\n";
    
    if (-e $responses_log) {
        open(my $log_fh, '<', $responses_log) or die "[Error] [$timestamp] Cannot open responses log file: $!";
        while (<$log_fh>) {
            print $fh "$_";
        }
        close($log_fh);
    }
    
    print $fh "</pre>\n";
    print $fh "</body>\n</html>\n";
    close($fh);
    
    return $report_file;
}

# Main program
my $url = parse_arguments();

# Immediately verify that $url is defined (not empty)
if (!defined $url || $url eq '') {
    die "[Error] [$timestamp] No URL was provided. Usage: $0 --url <URL>\n";
}

# Once we're sure $url is valid, proceed with the rest
my $output_folder      = create_output_folder();
my $vulnerabilities_log = "$output_folder/vulnerabilities.log";
my $permissions_log     = "$output_folder/permissions.log";
my $responses_log       = "$output_folder/responses.log";
my $verbose             = 1;  # Set to 0 to disable verbose output

my %options = (
    vulnerabilities_log => $vulnerabilities_log,
    responses_log       => $responses_log,
    verbose             => $verbose,
    tested_links        => \%visited_urls,
);
# Initialize the UserAgent
my $ua = LWP::UserAgent->new;

# Set the base URL for domain-specific crawling
$base_url = URI->new($url)->canonical;

# Create the output folder if it doesn't exist
mkdir $output_folder unless -d $output_folder;

# Initialize data structures to track tested links and vulnerabilities
#my %visited_urls;
my %vulnerabilities;

# Start crawling and testing vulnerabilities
crawl_and_test($ua, $url, \%options);

# Create an HTML report
#my $report_file = create_html_report($output_folder, $vulnerabilities_log, $responses_log);
my $report_file = create_html_report($output_folder, $vulnerabilities_log, $responses_log);
display_message("INFO", "HTML report saved to: $report_file");

# End of the program
