import os
import json
from aiohttp import web
import redis.asyncio as redis

# --- Configuration ---
# Use decode_responses=True to get strings back from Redis, not bytes
r = redis.Redis(host="localhost", port=6379, decode_responses=True)

# Initialize default Redis variables if they don't exist
r.setnx('waf_enabled', 'true') # WAF is enabled by default
r.setnx('visit', 0)

# --- API Endpoints (Return JSON/Text) ---

async def api_info(request):
    """
    GET /admin/api/info
    Returns the current SIEM/WAF status and metrics as JSON.
    """
    try:
        # Fetch simple metrics
        visit_count = await r.get("visit") or '0'
        waf_status = await r.get("waf_enabled") or 'false'
        sqli_waf_status = await r.get("enable_sql_waf")
        xss_waf_status = await r.get("enable_xss_waf")

        # Fetch manual block count
        manual_blocks_count = await r.llen('manual_blocks') 
        
        # Fetch simulated logs (last 10 events)
        # Assuming logs are simple strings or JSON stored in a list
        logs = await r.lrange('waf_events', 0, 9)

        data = {
            "visit_count": visit_count,
            "waf_enabled": waf_status,
            "sqli_waf_status": sqli_waf_status,
            "xss_waf_status": xss_waf_status,
            "manual_blocks_count": manual_blocks_count,
            "logs": logs
        }

        return web.json_response(data)
    except Exception as e:
        print(f"Error in api_info: {e}")
        return web.Response(text="Internal Server Error fetching info.", status=500)

async def api_settings(request):
    """
    POST /admin/api/settings
    Handles configuration updates and actions.
    """
    try:
        data = await request.post()
    except Exception:
        return web.Response(text="Invalid POST data format.", status=400)

    # 1. Handle WAF Status Toggle
    if 'waf_status' in data:
        new_status = data['waf_status'].lower()
        if new_status in ['true', 'false']:
            r.set('waf_enabled', new_status)
            return web.Response(text=f"WAF status set to: {new_status}", status=200)
        else:
            return web.Response(text="Invalid value for waf_status. Must be 'true' or 'false'.", status=400)

    # 2. Handle Manual IP Block
    if 'block_ip' in data:
        ip_to_block = data['block_ip']
        if ip_to_block:
            # Pushes the IP to a Redis List for manual blocks
            r.lpush('manual_blocks', ip_to_block)
            # Simulate a log event for the action
            log_msg = f"MANUAL_BLOCK: IP {ip_to_block} added to manual block list."
            r.lpush('waf_events', log_msg) 
            return web.Response(text=f"IP {ip_to_block} blocked successfully.", status=200)
        else:
            return web.Response(text="IP address cannot be empty.", status=400)
    
    return web.Response(text="No valid setting or action provided.", status=400)

# --- Frontend Handler (Returns HTML) ---

async def admin_dashboard(request):
    """
    GET /admin
    Serves the main SIEM/WAF control panel HTML page.
    """
    # In a real application, you would read index.html from a static directory.
    # For this example, we return a simple placeholder or the full HTML.
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Agentic WAF SIEM Control Panel</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-50">
        <div class="container mx-auto p-6">
            <h1 class="text-3xl font-bold mb-8 text-gray-800">WAF SIEM Dashboard</h1>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
                
                <div class="bg-white p-6 rounded-lg shadow">
                    <h2 class="text-xl font-semibold text-gray-700">WAF Status</h2>
                    <p id="waf-status" class="text-3xl font-extrabold mt-2 text-yellow-500">Loading...</p>
                </div>

                <div class="bg-white p-6 rounded-lg shadow">
                    <h2 class="text-xl font-semibold text-gray-700">Total Visits</h2>
                    <p id="visit-count" class="text-3xl font-extrabold mt-2 text-blue-600">Loading...</p>
                </div>

                <div class="bg-white p-6 rounded-lg shadow">
                    <h2 class="text-xl font-semibold text-gray-700">Manually Blocked IPs</h2>
                    <p id="manual-blocks-count" class="text-3xl font-extrabold mt-2 text-red-600">Loading...</p>
                </div>

            </div>

            <div class="bg-white p-6 rounded-lg shadow mb-10">
                <h2 class="text-2xl font-bold mb-4 text-gray-800">WAF Configuration & Actions</h2>
                <div class="space-y-4">
                    
                    <form id="waf-toggle-form" class="flex items-center space-x-4 border p-4 rounded-md">
                        <label for="waf_status" class="font-medium text-gray-700">Set WAF State:</label>
                        <select id="waf_status" name="waf_status" class="p-2 border rounded-md focus:ring-blue-500 focus:border-blue-500">
                            <option value="true">Enable WAF</option>
                            <option value="false">Disable WAF</option>
                        </select>
                        <button type="submit" class="bg-green-500 hover:bg-green-600 text-white font-bold py-2 px-4 rounded-md transition duration-150">
                            Apply WAF Status
                        </button>
                    </form>

                    <form id="manual-block-form" class="flex items-center space-x-4 border p-4 rounded-md">
                        <label for="block_ip" class="font-medium text-gray-700">Manually Block IP:</label>
                        <input type="text" id="block_ip" name="block_ip" placeholder="e.g., 1.2.3.4" required class="p-2 border rounded-md w-64 focus:ring-red-500 focus:border-red-500">
                        <button type="submit" class="bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-4 rounded-md transition duration-150">
                            Block IP
                        </button>
                    </form>

                </div>
                <p id="settings-message" class="mt-4 font-semibold"></p>
            </div>

            <div class="bg-white p-6 rounded-lg shadow">
                <h2 class="text-2xl font-bold mb-4 text-gray-800">Recent WAF Events (Last 10)</h2>
                <div id="log-output" class="bg-gray-800 text-green-400 p-4 rounded-md text-sm font-mono overflow-auto max-h-96">
                    <p>Fetching logs...</p>
                </div>
            </div>

        </div>

        <script>
            
            const API_INFO_URL = '/admin/api/info';
            const API_SETTINGS_URL = '/admin/api/settings';

            // Function to fetch data and update dashboard
            async function fetchAndUpdateDashboard() {
                try {
                    const response = await fetch(API_INFO_URL);
                    if (!response.ok) {
                        throw new Error(\`HTTP error! status: \${response.status}\`);
                    }
                    const data = await response.json();

                    // Update metrics
                    const statusText = data.waf_enabled === 'true' ? 'ACTIVE' : 'INACTIVE';
                    const statusColor = data.waf_enabled === 'true' ? 'text-green-600' : 'text-red-600';

                    document.getElementById('waf-status').textContent = statusText;
                    document.getElementById('waf-status').className = 'text-3xl font-extrabold mt-2 ' + statusColor;
                    document.getElementById('visit-count').textContent = data.visit_count;
                    document.getElementById('manual-blocks-count').textContent = data.manual_blocks_count;
                    
                    // Set WAF toggle to current status
                    document.getElementById('waf_status').value = data.waf_enabled;

                    // Update logs
                    const logOutput = document.getElementById('log-output');
                    logOutput.innerHTML = '';
                    if (data.logs && data.logs.length > 0) {
                        data.logs.forEach(log => {
                            const p = document.createElement('p');
                            p.textContent = log;
                            logOutput.appendChild(p);
                        });
                    } else {
                        logOutput.innerHTML = '<p>No recent WAF events found.</p>';
                    }

                } catch (error) {
                    console.error("Failed to fetch dashboard data:", error);
                    document.getElementById('waf-status').textContent = 'Error';
                    document.getElementById('settings-message').textContent = \`Error fetching data: \${error.message}\`;
                }
            }

            // Function to handle form submissions
            async function handleSettingsForm(event, formData) {
                event.preventDefault();
                const form = event.target;
                const messageElement = document.getElementById('settings-message');
                messageElement.textContent = 'Applying setting...';
                messageElement.className = 'mt-4 font-semibold text-yellow-600';

                try {
                    const response = await fetch(API_SETTINGS_URL, {
                        method: 'POST',
                        body: formData
                    });

                    const responseText = await response.text();

                    if (response.ok) {
                        messageElement.textContent = \`Success: \${responseText}\`;
                        messageElement.className = 'mt-4 font-semibold text-green-600';
                        // Refresh metrics after successful change
                        fetchAndUpdateDashboard();
                    } else {
                        messageElement.textContent = \`Error: \${responseText}\`;
                        messageElement.className = 'mt-4 font-semibold text-red-600';
                    }

                } catch (error) {
                    console.error("Form submission failed:", error);
                    messageElement.textContent = 'Network or server error during submission.';
                    messageElement.className = 'mt-4 font-semibold text-red-600';
                }
            }

            // Event Listeners
            document.addEventListener('DOMContentLoaded', () => {
                fetchAndUpdateDashboard();
                
                // WAF Toggle Listener
                document.getElementById('waf-toggle-form').addEventListener('submit', (e) => {
                    const formData = new FormData(e.target);
                    // Remove other fields to ensure only waf_status is sent
                    if (formData.has('block_ip')) formData.delete('block_ip'); 
                    handleSettingsForm(e, formData);
                });

                // Manual Block Listener
                document.getElementById('manual-block-form').addEventListener('submit', (e) => {
                    const formData = new FormData(e.target);
                    // Remove other fields to ensure only block_ip is sent
                    if (formData.has('waf_status')) formData.delete('waf_status');
                    handleSettingsForm(e, formData);
                });
            });
        </script>
    </body>
    </html>
    """
    return web.Response(text=html_content, content_type='text/html')

# --- Login & Dummy Handlers (Unchanged/Simplified) ---

# The original Request handler for '/' which forwards to login
async def login_fwd(request):
    return web.HTTPFound('/login')

async def login(request):
    # Dummy login implementation
    if request.method == 'POST':
        # Simulate successful login and redirect to admin panel
        return web.HTTPFound('/admin')
    
    # Simple login page for GET request
    return web.Response(text="<h1>Login Page</h1><form method='post'><input type='text' name='user'><input type='password' name='pass'><button type='submit'>Login</button></form>", content_type='text/html')

# The original settings function is now replaced by api_settings but the route is kept for consistency if needed later.
# For this example, we'll route POST /admin to api_settings.
# async def settings(request):
#     pass

# --- Application Setup ---

app = web.Application()
app.add_routes([
    # Frontend Routes
    web.get('/', login_fwd),
    web.get('/login', login),
    web.post('/login', login),
    web.get('/admin', admin_dashboard), # Serves the HTML dashboard

    # API Routes for Dashboard Data & Configuration
    web.get('/admin/api/info', api_info), 
    web.post('/admin/api/settings', api_settings) # Handles POST requests for configuration
])

if __name__ == '__main__':
    # Add a dummy log entry for testing
    r.lpush('waf_events', json.dumps({"timestamp": "2025-12-14 19:00:00", "type": "INFO", "message": "SIEM started successfully."}))
    r.lpush('waf_events', json.dumps({"timestamp": "2025-12-14 19:01:15", "type": "ALERT", "message": "SQLi attempted from 8.8.8.8"}))
    r.lpush('waf_events', json.dumps({"timestamp": "2025-12-14 19:02:40", "type": "BLOCK", "message": "IP 192.168.1.10 blocked by rate limit."}))
    
    web.run_app(app, port=1337)