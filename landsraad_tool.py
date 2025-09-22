import streamlit as st
import sqlite3
import pandas as pd
import math
import hashlib
import secrets
from typing import List, Tuple, Optional
import time
import re
import os
import csv
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv(), override=True)

# Authentication and user management
def init_auth_database():
    """Initialize authentication database"""
    conn = sqlite3.connect('dune_auth.db')
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guild_name TEXT UNIQUE NOT NULL,
        email TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    """Hash password with salt"""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}${pwd_hash}"

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash"""
    try:
        salt, pwd_hash = stored_hash.split('$')
        return hashlib.sha256((password + salt).encode()).hexdigest() == pwd_hash
    except:
        return False

def create_pending_user(guild_name: str, email: str, password: str) -> Tuple[bool, str]:
    """Create pending user registration (not stored in DB until verified)"""
    try:
        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return False, "Invalid email format"
        
        # Check if guild name or email already exists in verified users
        conn = sqlite3.connect('dune_auth.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE guild_name = ? OR email = ?', (guild_name, email))
        if cursor.fetchone():
            conn.close()
            return False, "Guild name or email already exists"
        conn.close()
        
        # Create verification token and store temporarily
        verification_token = secrets.token_urlsafe(32)
        password_hash = hash_password(password)
        
        # Store in session state temporarily
        st.session_state.pending_registration = {
            'guild_name': guild_name,
            'email': email,
            'password_hash': password_hash,
            'verification_token': verification_token
        }
        
        # Send verification email
        send_verification_email(email, guild_name, verification_token)
        
        return True, verification_token
    except Exception as e:
        return False, f"Error creating account: {str(e)}"

def send_verification_email(email: str, guild_name: str, token: str) -> bool:
    """Send verification email using configured service"""
    email_service = os.getenv('EMAIL_SERVICE', 'mock').lower()
    
    if email_service == 'mailgun':
        return send_mailgun_verification(email, guild_name, token)
    else:
        # Mock implementation
        st.session_state.mock_verification_token = token
        st.session_state.mock_verification_email = email
        return True

def send_mailgun_verification(email: str, guild_name: str, token: str) -> bool:
    """Send verification email using Mailgun API"""
    try:
        import requests
        
        api_key = os.getenv('MAILGUN_API_KEY')
        domain = os.getenv('MAILGUN_DOMAIN')
        api_url = os.getenv('MAILGUN_API_URL')
        from_email = os.getenv('MAILGUN_FROM_EMAIL', f'noreply@{domain}')
        
        if not api_key or not domain:
            st.error("Mailgun credentials not configured.")
            return False
        
        subject = f"Verify Your Guild Registration - {guild_name}"
        html_content = f"""
        <h2>Welcome to Dune: Awakening Landsraad Challenge Tracker!</h2>
        <p><strong>Guild:</strong> {guild_name}</p>
        <p>Please verify your email address by copying this verification token:</p>
        <div style="background-color: #f5f5f5; padding: 10px; margin: 10px 0; font-family: monospace; font-size: 16px;">
            {token}
        </div>
        <p>This token will expire in 24 hours.</p>
        """
        
        response = requests.post(
            f"{api_url}/v3/{domain}/messages",
            auth=("api", api_key),
            data={
                "from": from_email,
                "to": email,
                "subject": subject,
                "html": html_content
            },
            timeout=(10, 20)
        )
        print(response.content)
        print(response)
        
        st.write("requests response:", response.content)
        
        return response.status_code == 200
        
    except Exception as e:
        st.error(f"Failed to send verification email: {str(e)}")
        return False

def verify_user_and_create_account(token: str) -> bool:
    """Verify user token and create account in database"""
    if 'pending_registration' not in st.session_state:
        return False
    
    pending = st.session_state.pending_registration
    
    if pending.get('verification_token') != token:
        return False
    
    try:
        conn = sqlite3.connect('dune_auth.db')
        cursor = conn.cursor()
        
        # Final check for duplicates
        cursor.execute('SELECT id FROM users WHERE guild_name = ? OR email = ?', 
                      (pending['guild_name'], pending['email']))
        if cursor.fetchone():
            conn.close()
            return False
        
        # Create verified user account
        cursor.execute('''
        INSERT INTO users (guild_name, email, password_hash)
        VALUES (?, ?, ?)
        ''', (pending['guild_name'], pending['email'], pending['password_hash']))
        
        conn.commit()
        conn.close()
        
        # Clear pending registration
        del st.session_state.pending_registration
        
        return True
        
    except Exception:
        return False

def authenticate_user(guild_name: str, password: str) -> Tuple[bool, str]:
    """Authenticate user login"""
    conn = sqlite3.connect('dune_auth.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT password_hash FROM users WHERE guild_name = ?', (guild_name,))
    result = cursor.fetchone()
    
    if not result:
        conn.close()
        return False, "Guild not found"
    
    password_hash = result[0]
    
    if not verify_password(password, password_hash):
        conn.close()
        return False, "Invalid password"
    
    # Update last login
    cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE guild_name = ?', (guild_name,))
    conn.commit()
    conn.close()
    
    return True, "Login successful"

def get_user_database_name(guild_name: str) -> str:
    """Get guild-specific database name"""
    safe_name = "".join(c for c in guild_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
    safe_name = safe_name.replace(' ', '_').lower()
    return f'dune_inventory_{safe_name}.db'

def show_auth_interface():
    """Show authentication interface"""
    st.set_page_config(page_title="Dune: Awakening Item Tracker - Login", layout="centered")
    
    st.title("🏜️ Dune: Awakening - Landsraad Item Tracker")
    st.markdown("**Multi-Guild Landsraad Item Tracking System**")
    
    init_auth_database()
    
    tab1, tab2, tab3 = st.tabs(["🔑 Login", "📝 Register", "✅ Verify Email"])
    
    with tab1:
        st.header("Guild Login")
        
        with st.form("login_form"):
            guild_name = st.text_input("Guild Name")
            password = st.text_input("Password", type="password")
            login_button = st.form_submit_button("Login", type="primary")
            
            if login_button:
                if guild_name and password:
                    success, message = authenticate_user(guild_name, password)
                    if success:
                        st.session_state.authenticated = True
                        st.session_state.current_guild = guild_name
                        st.session_state.db_name = get_user_database_name(guild_name)
                        st.success("Login successful!")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error(message)
                else:
                    st.error("Please enter guild name and password")
    
    with tab2:
        st.header("Register New Guild")
        
        with st.form("register_form"):
            new_guild = st.text_input("Guild Name")
            email = st.text_input("Email Address")
            new_password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            register_button = st.form_submit_button("Register Guild", type="primary")
            
            if register_button:
                if not all([new_guild, email, new_password, confirm_password]):
                    st.error("Please fill in all fields")
                elif new_password != confirm_password:
                    st.error("Passwords don't match")
                elif len(new_password) < 6:
                    st.error("Password must be at least 6 characters")
                else:
                    success, result = create_pending_user(new_guild, email, new_password)
                    if success:
                        st.success("Registration initiated! Please check the verification tab.")
                        if os.getenv('EMAIL_SERVICE', 'mock').lower() == 'mock':
                            st.info("💡 **Demo Mode**: Check verification tab for token")
                    else:
                        st.error(result)
    
    with tab3:
        st.header("Email Verification")
        
        if hasattr(st.session_state, 'mock_verification_token'):
            st.info(f"📧 **Demo Token**: `{st.session_state.mock_verification_token}`")
        
        with st.form("verify_form"):
            verification_token = st.text_input("Verification Token")
            verify_button = st.form_submit_button("Verify Account", type="primary")
            
            if verify_button:
                if verification_token:
                    if verify_user_and_create_account(verification_token):
                        st.success("Email verified! Account created successfully. You can now login.")
                        if hasattr(st.session_state, 'mock_verification_token'):
                            del st.session_state.mock_verification_token
                    else:
                        st.error("Invalid verification token")
                else:
                    st.error("Please enter verification token")

# Database functions
def load_initial_items(db_name: str):
    """Load initial items from CSV file"""
    try:
        if not os.path.exists('item_list.csv'):
            return
        
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()
        
        # Check if database already has items
        cursor.execute('SELECT COUNT(*) FROM items')
        if cursor.fetchone()[0] > 0:
            conn.close()
            return
        
        # Load from CSV
        with open('item_list.csv', 'r', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            items_added = 0
            
            for row in csv_reader:
                try:
                    name = row.get('name', '').strip()
                    category = row.get('category', '').strip()
                    points_per_item = int(row.get('points_per_item', 0))
                    
                    if name and category and points_per_item > 0:
                        cursor.execute('''
                        INSERT OR IGNORE INTO items (name, category, points_per_item, current_stock)
                        VALUES (?, ?, ?, 0)
                        ''', (name, category, points_per_item))
                        items_added += 1
                        
                except (ValueError, KeyError):
                    continue
            
            conn.commit()
            if items_added > 0:
                st.success(f"Loaded {items_added} items from item_list.csv")
            
        conn.close()
        
    except Exception as e:
        st.error(f"Error loading initial items: {str(e)}")

def init_database():
    """Initialize the SQLite database"""
    db_name = st.session_state.get('db_name', 'dune_inventory.db')
    is_new_database = not os.path.exists(db_name)
    
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        category TEXT NOT NULL,
        points_per_item INTEGER NOT NULL,
        current_stock INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_item_name ON items(name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_category ON items(category)')
    
    conn.commit()
    conn.close()
    
    if is_new_database:
        load_initial_items(db_name)

def calculate_required_amount(points_per_item: int, target_points: int = 70000, weeks_lost: int = 0) -> int:
    """Calculate required amount with bonus multiplier"""
    bonus_multiplier = 1.0 + (weeks_lost * 0.2)
    effective_points = points_per_item * bonus_multiplier
    return math.ceil(target_points / effective_points)

def get_bonus_multiplier(weeks_lost: int) -> float:
    """Get bonus multiplier"""
    return 1.0 + (weeks_lost * 0.2)

def get_effective_points(points_per_item: int, weeks_lost: int) -> float:
    """Calculate effective points with bonus"""
    return points_per_item * get_bonus_multiplier(weeks_lost)

def get_all_items() -> List[Tuple]:
    """Get all items from database"""
    db_name = st.session_state.get('db_name', 'dune_inventory.db')
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('SELECT name, category, points_per_item, current_stock FROM items ORDER BY name')
    items = cursor.fetchall()
    conn.close()
    return items

def get_item_by_name(item_name: str) -> Optional[Tuple]:
    """Get specific item by name"""
    db_name = st.session_state.get('db_name', 'dune_inventory.db')
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('SELECT name, category, points_per_item, current_stock FROM items WHERE name = ?', (item_name,))
    item = cursor.fetchone()
    conn.close()
    return item

def update_item_stock(item_name: str, new_stock: int):
    """Update item stock"""
    db_name = st.session_state.get('db_name', 'dune_inventory.db')
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
    UPDATE items 
    SET current_stock = ?, updated_at = CURRENT_TIMESTAMP 
    WHERE name = ?
    ''', (new_stock, item_name))
    conn.commit()
    conn.close()

def add_item(name: str, category: str, points_per_item: int, current_stock: int = 0):
    """Add new item to database"""
    db_name = st.session_state.get('db_name', 'dune_inventory.db')
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    try:
        cursor.execute('''
        INSERT INTO items (name, category, points_per_item, current_stock)
        VALUES (?, ?, ?, ?)
        ''', (name, category, points_per_item, current_stock))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_categories() -> List[str]:
    """Get all unique categories"""
    db_name = st.session_state.get('db_name', 'dune_inventory.db')
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('SELECT DISTINCT category FROM items ORDER BY category')
    categories = [row[0] for row in cursor.fetchall()]
    conn.close()
    return categories

def search_items(search_term: str, category_filter: str = None) -> List[Tuple]:
    """Search items by name with optional category filter"""
    db_name = st.session_state.get('db_name', 'dune_inventory.db')
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    
    if category_filter and category_filter != "All Categories":
        cursor.execute('''
        SELECT name, category, points_per_item, current_stock 
        FROM items 
        WHERE name LIKE ? AND category = ?
        ORDER BY name
        ''', (f'%{search_term}%', category_filter))
    else:
        cursor.execute('''
        SELECT name, category, points_per_item, current_stock 
        FROM items 
        WHERE name LIKE ?
        ORDER BY name
        ''', (f'%{search_term}%',))
    
    items = cursor.fetchall()
    conn.close()
    return items

def update_stock_from_csv(csv_file) -> Tuple[int, int, List[str]]:
    """Update item stock from uploaded CSV file"""
    try:
        db_name = st.session_state.get('db_name', 'dune_inventory.db')
        conn = sqlite3.connect(db_name)
        cursor = conn.cursor()
        
        # Read CSV content
        csv_content = csv_file.read().decode('utf-8')
        csv_reader = csv.DictReader(csv_content.splitlines())
        
        updates_made = 0
        items_not_found = []
        total_processed = 0
        
        for row in csv_reader:
            total_processed += 1
            
            # Get name (case insensitive)
            item_name = row.get('name', '').strip()
            if not item_name:
                continue
                
            # Get current_stock and convert to integer
            stock_value = row.get('current_stock', '0').strip()
            try:
                # Handle various formats - remove commas, convert to int
                stock_value = stock_value.replace(',', '').replace(' ', '')
                current_stock = int(float(stock_value))  # float first to handle decimals, then int
                if current_stock < 0:
                    current_stock = 0  # Don't allow negative values
            except (ValueError, TypeError):
                continue  # Skip invalid stock values
            
            # Find matching item (case insensitive)
            cursor.execute('''
            SELECT name FROM items WHERE LOWER(name) = LOWER(?)
            ''', (item_name,))
            
            result = cursor.fetchone()
            if result:
                actual_name = result[0]
                # Update the stock
                cursor.execute('''
                UPDATE items 
                SET current_stock = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE LOWER(name) = LOWER(?)
                ''', (current_stock, item_name))
                updates_made += 1
            else:
                items_not_found.append(item_name)
        
        conn.commit()
        conn.close()
        
        return updates_made, total_processed, items_not_found
        
    except Exception as e:
        st.error(f"Error processing CSV: {str(e)}")
        return 0, 0, []

def process_dataframe_edits(edited_df, original_df):
    """Process edits from data_editor and update database"""
    changes_made = False
    
    for idx, row in edited_df.iterrows():
        original_row = original_df.iloc[idx]
        
        if 'In Stock' in row and 'In Stock' in original_row:
            try:
                new_stock = int(row['In Stock'])
                old_stock = int(original_row['In Stock'])
                
                if new_stock != old_stock:
                    item_name = row['Item']
                    update_item_stock(item_name, new_stock)
                    changes_made = True
            except (ValueError, TypeError):
                continue
    
    return changes_made

# Main UI
def main():
    if not st.session_state.get('authenticated', False):
        show_auth_interface()
        return
    
    st.set_page_config(page_title="Dune: Awakening Item Tracker", layout="wide")
    
    # Header with logout
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("🏜️ Dune: Awakening - Landsraad Item Tracker")
        st.markdown(f"**Guild:** {st.session_state.get('current_guild', 'Unknown')}")
    
    with col2:
        if st.button("🚪 Logout", type="secondary"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    
    init_database()
    all_items = get_all_items()
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Challenge Settings")
        
        weeks_lost = st.selectbox(
            "Consecutive Weeks Lost",
            options=[0, 1, 2, 3, 4, 5],
            help="Your faction's consecutive weeks without winning Landsraad"
        )
        
        bonus_multiplier = get_bonus_multiplier(weeks_lost)
        if weeks_lost > 0:
            st.info(f"🎯 Bonus: +{weeks_lost * 20}% points ({bonus_multiplier:.1f}x multiplier)")
        
        st.subheader("🎁 Reward Targets")
        reward_targets = {
            "10K Solari": 700,
            "Mk5 Reward": 3500,
            "Component Reward": 7000,
            "Mk6 Reward": 10500,
            "Color Swatches": 14000,
            "Complete Win": 70000
        }
        
        selected_reward = st.selectbox(
            "Select Target Reward",
            options=list(reward_targets.keys()),
            index=5
        )
        
        target_points = reward_targets[selected_reward]
        st.write(f"Target Points: **{target_points:,}**")
        
        st.divider()
        
        st.header("🔍 Item Search")
        
        categories = ["All Categories"] + get_categories()
        category_filter = st.selectbox("Filter by Category", categories)
        search_term = st.text_input("Search Items", placeholder="Type item name...")
        
        if search_term:
            filtered_items = search_items(search_term, category_filter)
        else:
            filtered_items = all_items
            if category_filter != "All Categories":
                filtered_items = [item for item in all_items if item[1] == category_filter]
        
        selected_item = None
        if filtered_items:
            item_names = [item[0] for item in filtered_items]
            
            if "quick_selected_item" in st.session_state:
                selected_item_name = st.session_state.quick_selected_item
                del st.session_state.quick_selected_item
                default_index = item_names.index(selected_item_name) if selected_item_name in item_names else 0
            else:
                default_index = 0
            
            selected_item_name = st.selectbox("Select Item", item_names, index=default_index)
            selected_item = get_item_by_name(selected_item_name)
            
            if selected_item:
                st.success(f"✅ **Selected:** {selected_item[0]}")
                st.write(f"**Category:** {selected_item[1]}")
                st.write(f"**In Stock:** {selected_item[3]:,}")
        else:
            st.info("No items found")
        
        st.divider()
        
        st.header("📦 Item Management")
        
        with st.expander("Add New Item"):
            with st.form("add_item_form"):
                new_name = st.text_input("Item Name")
                new_category = st.text_input("Category")
                new_points = st.number_input("Points per Item", min_value=1, value=100)
                new_stock = st.number_input("Initial Stock", min_value=0, value=0)
                
                if st.form_submit_button("Add Item"):
                    if new_name and new_category:
                        if add_item(new_name, new_category, new_points, new_stock):
                            st.success(f"Added {new_name}")
                            st.rerun()
                        else:
                            st.error("Item already exists")
                    else:
                        st.error("Please fill in all required fields")
        
        with st.expander("Import Stock from CSV"):
            st.markdown("**Upload a CSV file to update current stock values**")
            st.markdown("Required columns: `name`, `current_stock`")
            st.markdown("- Case insensitive item name matching")
            st.markdown("- Stock values will be converted to integers")
            st.markdown("- Invalid values will be skipped")
            
            uploaded_file = st.file_uploader(
                "Choose CSV file",
                type=['csv'],
                help="CSV format: name,current_stock"
            )
            
            if uploaded_file is not None:
                if st.button("Import Stock Updates", type="primary"):
                    updates_made, total_processed, items_not_found = update_stock_from_csv(uploaded_file)
                    
                    if updates_made > 0:
                        st.success(f"✅ Updated stock for {updates_made} items")
                        
                        if items_not_found:
                            st.warning(f"⚠️ {len(items_not_found)} items not found in database:")
                            for item in items_not_found[:10]:  # Show first 10
                                st.text(f"- {item}")
                            if len(items_not_found) > 10:
                                st.text(f"... and {len(items_not_found) - 10} more")
                        
                        st.rerun()
                    else:
                        st.error("No valid updates found in CSV file")
                        if items_not_found:
                            st.info("Items not found:")
                            for item in items_not_found[:5]:
                                st.text(f"- {item}")
            
            # Show example format
            with st.expander("Example CSV Format"):
                st.code('''name,current_stock
Spice,1500
Water,750
Solari,2000
"Advanced Machinery",100''', language='csv')
    
    # Main content
    st.header("📊 Item Details")
    
    if selected_item:
        name, category, points_per_item, current_stock = selected_item
        
        effective_points = get_effective_points(points_per_item, weeks_lost)
        required_amount = calculate_required_amount(points_per_item, target_points, weeks_lost)
        still_needed = max(0, required_amount - current_stock)
        completion_percentage = min(100, (current_stock / required_amount) * 100)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Category", category)
            if weeks_lost > 0:
                st.metric("Points per Item", f"{points_per_item} → {effective_points:.1f}", 
                         delta=f"{bonus_multiplier:.1f}x bonus")
            else:
                st.metric("Points per Item", f"{points_per_item}")
            st.metric("Required Amount", f"{required_amount:,}")
        
        with col2:
            st.metric("Still Needed", f"{still_needed:,}")
            st.metric("Completion", f"{completion_percentage:.1f}%")
            st.progress(completion_percentage / 100)
        
        st.info(f"🎯 Target: **{selected_reward}** ({target_points:,} points)")
        
        st.subheader("Update Stock")
        new_stock = st.number_input("In Stock", min_value=0, value=current_stock, key=f"stock_{name}")
        
        col_update, col_quick = st.columns([1, 2])
        
        with col_update:
            if st.button("Update Stock", type="primary"):
                update_item_stock(name, new_stock)
                st.success("Stock updated!")
                st.rerun()
        
        with col_quick:
            st.write("Quick Actions:")
            quick_cols = st.columns(4)
            
            with quick_cols[0]:
                if st.button("+10"):
                    update_item_stock(name, current_stock + 10)
                    st.rerun()
            
            with quick_cols[1]:
                if st.button("+100"):
                    update_item_stock(name, current_stock + 100)
                    st.rerun()
            
            with quick_cols[2]:
                if st.button("+1000"):
                    update_item_stock(name, current_stock + 1000)
                    st.rerun()
            
            with quick_cols[3]:
                if st.button("Complete"):
                    update_item_stock(name, required_amount)
                    st.rerun()
        
        # Status display
        completions_achieved = current_stock // required_amount
        items_for_next = required_amount - (current_stock % required_amount) if current_stock % required_amount != 0 else 0
        
        if completions_achieved == 0:
            if still_needed == 0:
                st.success(f"✅ 1x {selected_reward} Complete!")
            elif completion_percentage >= 50:
                st.warning(f"⚠️ {still_needed:,} needed for 1x {selected_reward} ({completion_percentage:.1f}% complete)")
            else:
                st.error(f"❌ {still_needed:,} needed for 1x {selected_reward} ({completion_percentage:.1f}% complete)")
        else:
            if items_for_next == 0:
                st.success(f"✅ {completions_achieved}x {selected_reward} Complete!")
            else:
                st.info(f"🎯 {completions_achieved}x {selected_reward} complete - {items_for_next:,} needed for #{completions_achieved + 1}")
    else:
        st.info("Select an item from the sidebar to view details")
    
    # Overview table
    st.header("📋 Inventory Overview")
    
    col1, col2 = st.columns(2)
    with col1:
        multi_column_view = st.checkbox("Multi-Column View", value=False)
    with col2:
        editable_mode = st.checkbox("Edit Stock", value=False, help="Allow editing Current Stock")
    
    if all_items:
        overview_data = []
        for item in all_items:
            name, category, points_per_item, current_stock = item
            effective_points = get_effective_points(points_per_item, weeks_lost)
            required = calculate_required_amount(points_per_item, target_points, weeks_lost)
            needed = max(0, required - current_stock)
            completion = min(100, (current_stock / required) * 100)
            
            completions_achieved = current_stock // required
            items_for_next = required - (current_stock % required) if current_stock % required != 0 else 0
            
            if completions_achieved == 0:
                status = f"{needed:,} needed for #1"
            elif items_for_next == 0:
                status = f"{completions_achieved}x covered"
            else:
                status = f"{completions_achieved}x covered - {items_for_next:,} needed for #{completions_achieved + 1}"
            
            points_display = f"{points_per_item} → {effective_points:.1f}" if weeks_lost > 0 else str(points_per_item)
            
            if multi_column_view:
                overview_data.append({
                    "Item": name,
                    "Category": category,
                    "In Stock": current_stock,
                    "Required": required,
                    "Status": status
                })
            else:
                overview_data.append({
                    "Item": name,
                    "Category": category,
                    "Points/Item": points_display,
                    "In Stock": current_stock,
                    "Required": required,
                    "Still Needed": needed,
                    "Completion %": f"{completion:.1f}%",
                    "Status": status
                })
        
        df = pd.DataFrame(overview_data)
        original_df = df.copy() if editable_mode else None
        
        # Sorting
        if not multi_column_view:
            sort_col1, sort_col2 = st.columns([1, 3])
            with sort_col1:
                sort_by = st.selectbox("Sort by:", df.columns.tolist())
            with sort_col2:
                ascending = st.checkbox("Ascending", value=True)
            
            if sort_by == "Item":
                df = df.sort_values(by=sort_by, ascending=ascending)
            else:
                df = df.sort_values(by=[sort_by, "Item"], ascending=[ascending, True])
        
        # Format for display if not editable
        if not editable_mode:
            display_df = df.copy()
            for col in ['In Stock', 'Required', 'Still Needed']:
                if col in display_df.columns:
                    display_df[col] = display_df[col].apply(lambda x: f"{x:,}")
        else:
            display_df = df.copy()
        
        # Display table
        if multi_column_view:
            # Split dataframe into multiple columns for better visibility
            num_items = len(display_df)
            items_per_column = max(10, num_items // 3)  # At least 10 items per column, max 3 columns
            
            if num_items <= 20:
                # Small dataset - use 2 columns
                mid_point = num_items // 2
                height = int(36.25 * (max(mid_point, num_items - mid_point) + 1))
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader(f"Items 1-{mid_point}")
                    if editable_mode:
                        edited_df1 = st.data_editor(
                            display_df.iloc[:mid_point], 
                            use_container_width=True, 
                            hide_index=True, 
                            height=height,
                            column_config={
                                "In Stock": st.column_config.NumberColumn(
                                    "In Stock",
                                    min_value=0,
                                    step=1,
                                    format="%d"
                                )
                            },
                            disabled=[col for col in display_df.columns if col != "In Stock"]
                        )
                    else:
                        st.dataframe(display_df.iloc[:mid_point], use_container_width=True, hide_index=True, height=height)
                
                with col2:
                    st.subheader(f"Items {mid_point + 1}-{num_items}")
                    if editable_mode:
                        edited_df2 = st.data_editor(
                            display_df.iloc[mid_point:], 
                            use_container_width=True, 
                            hide_index=True, 
                            height=height,
                            column_config={
                                "In Stock": st.column_config.NumberColumn(
                                    "In Stock",
                                    min_value=0,
                                    step=1,
                                    format="%d"
                                )
                            },
                            disabled=[col for col in display_df.columns if col != "In Stock"]
                        )
                    else:
                        st.dataframe(display_df.iloc[mid_point:], use_container_width=True, hide_index=True, height=height)
                
                # Process edits if in edit mode
                if editable_mode:
                    # Combine edited dataframes
                    edited_combined = pd.concat([edited_df1, edited_df2], ignore_index=True)
                    if process_dataframe_edits(edited_combined, original_df):
                        st.success("✅ Stock updated!")
                        st.rerun()
                        
            else:
                # Larger dataset - use 3 columns
                first_split = items_per_column
                second_split = items_per_column * 2
                
                items_last_column = num_items - second_split
                max_items = max(items_per_column, items_last_column)
                height = int(36.25 * (max_items + 1))
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.subheader(f"Items 1-{first_split}")
                    if editable_mode:
                        edited_df1 = st.data_editor(
                            display_df.iloc[:first_split], 
                            use_container_width=True, 
                            hide_index=True, 
                            height=height,
                            column_config={
                                "In Stock": st.column_config.NumberColumn(
                                    "In Stock",
                                    min_value=0,
                                    step=1,
                                    format="%d"
                                )
                            },
                            disabled=[col for col in display_df.columns if col != "In Stock"]
                        )
                    else:
                        st.dataframe(display_df.iloc[:first_split], use_container_width=True, hide_index=True, height=height)
                
                with col2:
                    st.subheader(f"Items {first_split + 1}-{second_split}")
                    if editable_mode:
                        edited_df2 = st.data_editor(
                            display_df.iloc[first_split:second_split], 
                            use_container_width=True, 
                            hide_index=True, 
                            height=height,
                            column_config={
                                "In Stock": st.column_config.NumberColumn(
                                    "In Stock",
                                    min_value=0,
                                    step=1,
                                    format="%d"
                                )
                            },
                            disabled=[col for col in display_df.columns if col != "In Stock"]
                        )
                    else:
                        st.dataframe(display_df.iloc[first_split:second_split], use_container_width=True, hide_index=True, height=height)
                
                with col3:
                    st.subheader(f"Items {second_split + 1}-{num_items}")
                    if editable_mode:
                        edited_df3 = st.data_editor(
                            display_df.iloc[second_split:], 
                            use_container_width=True, 
                            hide_index=True, 
                            height=height,
                            column_config={
                                "In Stock": st.column_config.NumberColumn(
                                    "In Stock",
                                    min_value=0,
                                    step=1,
                                    format="%d"
                                )
                            },
                            disabled=[col for col in display_df.columns if col != "In Stock"]
                        )
                    else:
                        st.dataframe(display_df.iloc[second_split:], use_container_width=True, hide_index=True, height=height)
                
                # Process edits if in edit mode
                if editable_mode:
                    # Combine edited dataframes
                    edited_combined = pd.concat([edited_df1, edited_df2, edited_df3], ignore_index=True)
                    if process_dataframe_edits(edited_combined, original_df):
                        st.success("✅ Stock updated!")
                        st.rerun()
        elif editable_mode:
            edited_df = st.data_editor(
                display_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "In Stock": st.column_config.NumberColumn(
                        "In Stock",
                        min_value=0,
                        step=1,
                        format="%d"
                    )
                },
                disabled=[col for col in display_df.columns if col != "In Stock"]
            )
            
            if process_dataframe_edits(edited_df, original_df):
                st.success("✅ Stock updated!")
                st.rerun()
        else:
            st.data_editor(
                display_df,
                use_container_width=True,
                hide_index=True,
                disabled=True,
                column_config={
                    col: st.column_config.TextColumn(col, disabled=True) 
                    for col in display_df.columns
                }
            )
        
        # Quick item selector
        with st.expander("📋 Quick Item Selector", expanded=False):
            st.markdown("Click any item to select it in the main interface:")
            
            categories = {}
            for item in all_items:
                name, category, points_per_item, current_stock = item
                if category not in categories:
                    categories[category] = []
                categories[category].append(name)
            
            if categories:
                category_names = list(categories.keys())
                num_cols = min(3, len(category_names))
                cols = st.columns(num_cols)
                
                for idx, category in enumerate(category_names):
                    with cols[idx % num_cols]:
                        st.write(f"**{category}**")
                        for item_name in sorted(categories[category]):
                            if st.button(item_name, key=f"quick_select_{item_name}", use_container_width=True):
                                st.session_state.quick_selected_item = item_name
                                st.rerun()
    
    # Statistics
    if all_items:
        st.header("📈 Statistics")
        
        total_items = len(all_items)
        completed_tasks = sum(1 for item in all_items if item[3] >= calculate_required_amount(item[2], target_points, weeks_lost))
        completion_rate = (completed_tasks / total_items) * 100 if total_items > 0 else 0
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Items", total_items)
        
        with col2:
            st.metric("Completed Tasks", completed_tasks)
        
        with col3:
            st.metric("Overall Completion", f"{completion_rate:.1f}%")

if __name__ == "__main__":
    main()
