"""
Vulnerable Flask Application - XXE Security Demo
DELIBERATELY INSECURE - For educational purposes only!

This application intentionally contains XXE vulnerabilities.
DO NOT use in production or deploy to public servers.
"""

from flask import Flask, request, render_template_string, jsonify
from lxml import etree
import os

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory if it doesn't exist
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def parse_xml_vulnerable(xml_content):
    """
    VULNERABLE XML parser - External entities are ENABLED
    This is intentionally insecure for demonstration purposes!
    """
    try:
        # Create parser with external entities ENABLED
        parser = etree.XMLParser(
            resolve_entities=True,  # VULNERABLE: Enable external entities
            no_network=False,  # VULNERABLE: Allow network access
            dtd_validation=False,
            load_dtd=True  # VULNERABLE: Load DTD
        )

        # Parse the XML
        root = etree.fromstring(xml_content.encode('utf-8'), parser)

        # Extract data from XML
        result = {
            'success': True,
            'parsed_data': extract_data(root),
            'message': 'XML parsed successfully'
        }

        return result

    except etree.XMLSyntaxError as e:
        return {
            'success': False,
            'error': f'XML Syntax Error: {str(e)}',
            'message': 'Failed to parse XML'
        }
    except Exception as e:
        return {
            'success': False,
            'error': f'Error: {str(e)}',
            'message': 'An error occurred'
        }

def extract_data(root):
    """
    Extract data from parsed XML tree
    """
    data = {}

    # Get root tag name
    data['root_tag'] = root.tag

    # Get all text content
    data['text_content'] = root.text or ''

    # Get all child elements
    children = []
    for child in root:
        child_data = {
            'tag': child.tag,
            'text': child.text or '',
            'attributes': dict(child.attrib)
        }
        children.append(child_data)

    data['children'] = children

    # Convert entire tree to string for display
    data['xml_string'] = etree.tostring(root, encoding='unicode', pretty_print=True)

    return data

@app.route('/')
def index():
    """
    Home page with simple XML test form
    """
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>XXE Vulnerable App - XML Parser</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 900px;
                margin: 50px auto;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }
            h1 {
                color: #d32f2f;
            }
            .warning {
                background-color: #fff3cd;
                border-left: 4px solid #ffc107;
                padding: 15px;
                margin: 20px 0;
            }
            textarea {
                width: 100%;
                min-height: 200px;
                font-family: 'Courier New', monospace;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            button {
                background-color: #d32f2f;
                color: white;
                padding: 12px 30px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 16px;
                margin-top: 10px;
            }
            button:hover {
                background-color: #b71c1c;
            }
            .result {
                margin-top: 20px;
                padding: 15px;
                background-color: #f9f9f9;
                border-radius: 4px;
                border: 1px solid #ddd;
            }
            pre {
                background-color: #272822;
                color: #f8f8f2;
                padding: 15px;
                border-radius: 4px;
                overflow-x: auto;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>⚠️ XXE Vulnerable XML Parser</h1>
            
            <div class="warning">
                <strong>WARNING:</strong> This application is intentionally vulnerable to XXE attacks.
                For educational purposes only. DO NOT deploy to production!
            </div>
            
            <h2>Test XML Parser</h2>
            <p>Enter XML content below to parse:</p>
            
            <form method="POST" action="/parse">
                <textarea name="xml_content" placeholder="Enter XML here...">
<?xml version="1.0" encoding="UTF-8"?>
<user>
    <name>John Doe</name>
    <email>john@example.com</email>
    <role>user</role>
</user>
                </textarea>
                <br>
                <button type="submit">Parse XML</button>
            </form>
            
            <h3>Example Payloads:</h3>
            <p><strong>Normal XML:</strong></p>
            <pre>&lt;?xml version="1.0"?&gt;
            &lt;data&gt;
                &lt;message&gt;Hello World&lt;/message&gt;
            &lt;/data&gt;</pre>
            
            <p><strong>XXE File Disclosure:</strong></p>
            <pre>&lt;?xml version="1.0"?&gt;
            &lt;!DOCTYPE foo [
              &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;
            ]&gt;
            &lt;data&gt;&amp;xxe;&lt;/data&gt;</pre>
        </div>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/parse', methods=['POST'])
def parse_xml():
    """
    Parse XML submitted via POST request
    """
    xml_content = request.form.get('xml_content', '')

    if not xml_content:
        return jsonify({
            'success': False,
            'error': 'No XML content provided'
        }), 400

    # Parse XML (vulnerable!)
    result = parse_xml_vulnerable(xml_content)

    # Return result as HTML
    if result['success']:
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Parse Result</title>
            <style>
                 body {{
                    font-family: Arial, sans-serif;
                    max-width: 900px;
                    margin: 50px auto;
                    padding: 20px;
                    background-color: #f5f5f5;
                }}
                .container {{
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .success {{
                    background-color: #d4edda;
                    border-left: 4px solid #28a745;
                    padding: 15px;
                    margin: 20px 0;
                }}
                pre {{
                    background-color: #272822;
                    color: #f8f8f2;
                    padding: 15px;
                    border-radius: 4px;
                    overflow-x: auto;
                }}
                a {{
                    color: #d32f2f;
                    text-decoration: none;
                }}
                a:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>✅ XML Parsed Successfully</h1>
                
                <div class="success">
                    {result['message']}
                </div>
                
                <h2>Parsed Data:</h2>
                <pre>{result['parsed_data']}</pre>
                
                <p><a href="/">← Back to Parser</a></p>
            </div>
        </body>
        </html>
        """
        return render_template_string(html)
    else:
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Parse Error</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    max-width: 900px;
                    margin: 50px auto;
                    padding: 20px;
                    background-color: #f5f5f5;
                }}
                .container {{
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .error {{
                    background-color: #f8d7da;
                    border-left: 4px solid #dc3545;
                    padding: 15px;
                    margin: 20px 0;
                }}
                a {{
                    color: #d32f2f;
                    text-decoration: none;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>❌ Parse Error</h1>

                <div class="error">
                    <strong>Error:</strong> {result.get('error', 'Unknown error')}
                </div>

                <p><a href="/">← Back to Parser</a></p>
            </div>
        </body>
        </html>
        """
        return render_template_string(html), 400

@app.route('/api/parse', methods=['POST'])
def api_parse_xml():
    """
    API endpoint for XML parsing (returns JSON)
    Useful for testing with curl or Burp Suite
    """
    # Accept both form data and raw body
    if request.content_type == 'application/xml' or request.content_type == 'text/xml':
        xml_content = request.data.decode('utf-8')
    else:
        xml_content = request.form.get('xml_content') or request.json.get('xml_content', '')

    if not xml_content:
        return jsonify({
            'success': False,
            'error': 'No XML content provided'
        }), 400

    result = parse_xml_vulnerable(xml_content)
    return jsonify(result)

@app.route('/health')
def health():
    """
    Health check endpoint
    """
    return jsonify({
        'status': 'running',
        'app': 'XXE Vulnerable Application',
        'version': '1.0.0',
        'warning': 'This application is intentionally vulnerable!'
    })


if __name__ == '__main__':
    print("=" * 60)
    print("⚠️  XXE VULNERABLE APPLICATION")
    print("=" * 60)
    print("This application is INTENTIONALLY INSECURE!")
    print("For educational purposes only.")
    print()
    print("🌐 Server starting on http://127.0.0.1:5000")
    print("=" * 60)

    app.run(debug=True, host='127.0.0.1', port=5000)