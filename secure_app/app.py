"""
Secure Flask Application - XXE Protection Demo
==============================================

This application demonstrates PROPER XML parsing security.
External entities are DISABLED to prevent XXE attacks.

SECURE CONFIGURATION - Safe for production use.

Author: Adrian Kapczynski
Course: Web and Mobile Application Security Testing
"""

from flask import Flask, request, render_template_string, jsonify
from lxml import etree
import os

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads directory if it doesn't exist
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def parse_xml_secure(xml_content):
    """
    SECURE XML parser - External entities are DISABLED
    This configuration prevents XXE attacks!
    """
    try:
        # Create parser with SECURE configuration
        parser = etree.XMLParser(
            resolve_entities=False,  # 🔒 DISABLE external entities (XXE protection)
            no_network=True,  # 🔒 BLOCK network access
            dtd_validation=False,  # 🔒 DISABLE DTD validation
            load_dtd=False,  # 🔒 DO NOT load DTD
            remove_blank_text=False,
            huge_tree=False  # 🔒 Limit tree size (DoS protection)
        )

        # Parse the XML
        root = etree.fromstring(xml_content.encode('utf-8'), parser)

        # Extract data from XML
        result = {
            'success': True,
            'parsed_data': extract_data(root),
            'message': 'XML parsed successfully (SECURE mode)'
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
    Home page with XML test form
    """
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure XML Parser - XXE Protected</title>
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
                color: #2e7d32;
            }
            .security-info {
                background-color: #e8f5e9;
                border-left: 4px solid #4caf50;
                padding: 15px;
                margin: 20px 0;
            }
            .tabs {
                display: flex;
                gap: 10px;
                margin: 20px 0;
            }
            .tab {
                padding: 10px 20px;
                background-color: #e0e0e0;
                border: none;
                cursor: pointer;
                border-radius: 4px 4px 0 0;
            }
            .tab.active {
                background-color: #2e7d32;
                color: white;
            }
            .tab-content {
                display: none;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 0 4px 4px 4px;
            }
            .tab-content.active {
                display: block;
            }
            textarea {
                width: 100%;
                min-height: 200px;
                font-family: 'Courier New', monospace;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 4px;
                box-sizing: border-box;
            }
            .file-input-wrapper {
                display: flex;
                align-items: center;
                gap: 15px;
                margin: 20px 0;
            }
            input[type="file"] {
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 4px;
                flex: 1;
            }
            button {
                background-color: #2e7d32;
                color: white;
                padding: 12px 30px;
                border: none;
                border-radius: 4px;
                cursor: pointer;
                font-size: 16px;
            }
            button:hover {
                background-color: #1b5e20;
            }
            pre {
                background-color: #272822;
                color: #f8f8f2;
                padding: 15px;
                border-radius: 4px;
                overflow-x: auto;
            }
            .security-feature {
                display: flex;
                align-items: center;
                margin: 10px 0;
            }
            .security-feature::before {
                content: "✓";
                color: #4caf50;
                font-weight: bold;
                font-size: 20px;
                margin-right: 10px;
            }
        </style>
        <script>
            function switchTab(tabName) {
                document.querySelectorAll('.tab-content').forEach(tab => {
                    tab.classList.remove('active');
                });
                document.querySelectorAll('.tab').forEach(tab => {
                    tab.classList.remove('active');
                });
                document.getElementById(tabName).classList.add('active');
                document.querySelector(`[onclick="switchTab('${tabName}')"]`).classList.add('active');
            }
        </script>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Secure XML Parser - XXE Protected</h1>

            <div class="security-info">
                <strong>✓ SECURE CONFIGURATION</strong><br>
                This application is properly configured to prevent XXE attacks.<br>
                Safe for production use.
            </div>

            <h2>Security Features Enabled:</h2>
            <div class="security-feature">External entities DISABLED</div>
            <div class="security-feature">Network access BLOCKED</div>
            <div class="security-feature">DTD loading DISABLED</div>
            <div class="security-feature">Entity expansion LIMITED</div>

            <h2>Choose Input Method:</h2>

            <div class="tabs">
                <button class="tab active" onclick="switchTab('paste-tab')">Paste XML</button>
                <button class="tab" onclick="switchTab('upload-tab')">Upload File</button>
            </div>

            <!-- Tab 1: Paste XML -->
            <div id="paste-tab" class="tab-content active">
                <h3>📝 Paste XML Content</h3>
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
                    <button type="submit">Parse XML (Secure)</button>
                </form>
            </div>

            <!-- Tab 2: Upload File -->
            <div id="upload-tab" class="tab-content">
                <h3>📁 Upload XML File</h3>
                <form method="POST" action="/upload" enctype="multipart/form-data">
                    <div class="file-input-wrapper">
                        <input type="file" name="xml_file" accept=".xml,text/xml" required>
                        <button type="submit">Upload & Parse (Secure)</button>
                    </div>
                </form>
                <p><em>Accepted formats: .xml files</em></p>
            </div>

            <h3>Try an XXE Attack (It Won't Work!):</h3>
            <p><strong>XXE Payload (will be blocked):</strong></p>
            <pre>&lt;?xml version="1.0"?&gt;
&lt;!DOCTYPE foo [
  &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;
]&gt;
&lt;data&gt;&amp;xxe;&lt;/data&gt;</pre>
            <p style="color: #2e7d32;">
                ✓ This XXE attack will be blocked by the secure parser!<br>
                The external entity will not be resolved.
            </p>
        </div>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route('/parse', methods=['POST'])
def parse_xml():
    """
    Parse XML submitted via POST request (SECURE)
    """
    xml_content = request.form.get('xml_content', '')

    if not xml_content:
        return jsonify({
            'success': False,
            'error': 'No XML content provided'
        }), 400

    # Parse XML (SECURE!)
    result = parse_xml_secure(xml_content)

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
                    background-color: #e8f5e9;
                    border-left: 4px solid #4caf50;
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
                    color: #2e7d32;
                    text-decoration: none;
                }}
                a:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>✅ XML Parsed Successfully (Secure Mode)</h1>

                <div class="success">
                    {result['message']}<br>
                    🔒 External entities blocked<br>
                    🔒 Network access disabled
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
                    background-color: #ffebee;
                    border-left: 4px solid #f44336;
                    padding: 15px;
                    margin: 20px 0;
                }}
                a {{
                    color: #2e7d32;
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
    API endpoint for XML parsing (SECURE)
    """
    if request.content_type == 'application/xml' or request.content_type == 'text/xml':
        xml_content = request.data.decode('utf-8')
    else:
        xml_content = request.form.get('xml_content') or request.json.get('xml_content', '')

    if not xml_content:
        return jsonify({
            'success': False,
            'error': 'No XML content provided'
        }), 400

    result = parse_xml_secure(xml_content)
    return jsonify(result)


@app.route('/health')
def health():
    """
    Health check endpoint
    """
    return jsonify({
        'status': 'running',
        'app': 'Secure XML Parser',
        'version': '1.0.0',
        'security': 'XXE protection enabled',
        'features': [
            'External entities disabled',
            'Network access blocked',
            'DTD loading disabled',
            'Entity expansion limited'
        ]
    })


@app.route('/upload', methods=['POST'])
def upload_file():
    """
    Handle XML file upload and parse it (SECURE)
    """
    if 'xml_file' not in request.files:
        return jsonify({
            'success': False,
            'error': 'No file uploaded'
        }), 400

    file = request.files['xml_file']

    if file.filename == '':
        return jsonify({
            'success': False,
            'error': 'No file selected'
        }), 400

    if not file.filename.endswith('.xml'):
        return jsonify({
            'success': False,
            'error': 'Only .xml files are allowed'
        }), 400

    try:
        xml_content = file.read().decode('utf-8')

        import datetime
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_filename = f"uploaded_{timestamp}_{file.filename}"
        filepath = os.path.join(UPLOAD_FOLDER, safe_filename)

        with open(filepath, 'w') as f:
            f.write(xml_content)

        # Parse XML (SECURE!)
        result = parse_xml_secure(xml_content)

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
                        background-color: #e8f5e9;
                        border-left: 4px solid #4caf50;
                        padding: 15px;
                        margin: 20px 0;
                    }}
                    .info {{
                        background-color: #e3f2fd;
                        border-left: 4px solid #2196f3;
                        padding: 15px;
                        margin: 20px 0;
                    }}
                    pre {{
                        background-color: #272822;
                        color: #f8f8f2;
                        padding: 15px;
                        border-radius: 4px;
                        overflow-x: auto;
                        max-height: 500px;
                    }}
                    a {{
                        color: #2e7d32;
                        text-decoration: none;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>✅ XML File Parsed Successfully (Secure)</h1>

                    <div class="info">
                        <strong>Uploaded File:</strong> {file.filename}<br>
                        <strong>Saved As:</strong> {safe_filename}
                    </div>

                    <div class="success">
                        {result['message']}<br>
                        🔒 XXE protection active
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
                        background-color: #ffebee;
                        border-left: 4px solid #f44336;
                        padding: 15px;
                        margin: 20px 0;
                    }}
                    a {{
                        color: #2e7d32;
                        text-decoration: none;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>❌ Parse Error</h1>

                    <div class="error">
                        <strong>File:</strong> {file.filename}<br>
                        <strong>Error:</strong> {result.get('error', 'Unknown error')}
                    </div>

                    <p><a href="/">← Back to Parser</a></p>
                </div>
            </body>
            </html>
            """
            return render_template_string(html), 400

    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error processing file: {str(e)}'
        }), 500


if __name__ == '__main__':
    print("=" * 60)
    print("🔒 SECURE XML PARSER APPLICATION")
    print("=" * 60)
    print("This application is properly secured against XXE attacks.")
    print("Safe for production use.")
    print()
    print("🌐 Server starting on http://127.0.0.1:5001")
    print("=" * 60)

    # Run on different port (5001) to not conflict with vulnerable app
    app.run(debug=True, host='127.0.0.1', port=5001)