import streamlit as st
import sqlite3
import pandas as pd
import math
from typing import List, Tuple, Optional

# Database setup
def init_database():
    """Initialize the SQLite database with required tables"""
    conn = sqlite3.connect('dune_inventory.db')
    cursor = conn.cursor()
    
    # Create items table
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
    
    # Create index for faster searches
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_item_name ON items(name)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_category ON items(category)')
    
    conn.commit()
    conn.close()

def calculate_required_amount(points_per_item: int, target_points: int = 70000, weeks_lost: int = 0) -> int:
    """Calculate required amount to reach target points with bonus multiplier"""
    # Apply bonus multiplier based on consecutive weeks lost
    bonus_multiplier = 1.0 + (weeks_lost * 0.2)
    effective_points = points_per_item * bonus_multiplier
    return math.ceil(target_points / effective_points)

def get_bonus_multiplier(weeks_lost: int) -> float:
    """Get bonus multiplier based on consecutive weeks lost"""
    return 1.0 + (weeks_lost * 0.2)

def get_effective_points(points_per_item: int, weeks_lost: int) -> float:
    """Calculate effective points per item with bonus"""
    return points_per_item * get_bonus_multiplier(weeks_lost)

def get_all_items() -> List[Tuple]:
    """Get all items from database"""
    conn = sqlite3.connect('dune_inventory.db')
    cursor = conn.cursor()
    cursor.execute('SELECT name, category, points_per_item, current_stock FROM items ORDER BY name')
    items = cursor.fetchall()
    conn.close()
    return items

def get_item_by_name(item_name: str) -> Optional[Tuple]:
    """Get specific item by name"""
    conn = sqlite3.connect('dune_inventory.db')
    cursor = conn.cursor()
    cursor.execute('SELECT name, category, points_per_item, current_stock FROM items WHERE name = ?', (item_name,))
    item = cursor.fetchone()
    conn.close()
    return item

def update_item_stock(item_name: str, new_stock: int):
    """Update item stock"""
    conn = sqlite3.connect('dune_inventory.db')
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
    conn = sqlite3.connect('dune_inventory.db')
    cursor = conn.cursor()
    try:
        cursor.execute('''
        INSERT INTO items (name, category, points_per_item, current_stock)
        VALUES (?, ?, ?, ?)
        ''', (name, category, points_per_item, current_stock))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Item already exists
    finally:
        conn.close()

def get_categories() -> List[str]:
    """Get all unique categories"""
    conn = sqlite3.connect('dune_inventory.db')
    cursor = conn.cursor()
    cursor.execute('SELECT DISTINCT category FROM items ORDER BY category')
    categories = [row[0] for row in cursor.fetchall()]
    conn.close()
    return categories

def search_items(search_term: str, category_filter: str = None) -> List[Tuple]:
    """Search items by name with optional category filter"""
    conn = sqlite3.connect('dune_inventory.db')
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

# Streamlit UI
def main():
    st.set_page_config(page_title="Dune: Awakening Item Tracker", layout="wide")
    
    st.title("🏜️ Dune: Awakening - Landsraad Challenge Tracker")
    st.markdown("Track your guild's inventory for weekly Landsraad challenges")
    
    # Initialize database
    init_database()
    
    # Get all items first
    all_items = get_all_items()
    
    # Initialize variables that will be used outside sidebar
    selected_item = None
    filtered_items = all_items
    weeks_lost = 0
    target_points = 70000
    selected_reward = "Complete Win"
    
    # Sidebar for settings and item management
    with st.sidebar:
        st.header("⚙️ Challenge Settings")
        
        # Consecutive weeks lost selector
        weeks_lost = st.selectbox(
            "Consecutive Weeks Lost",
            options=[0, 1, 2, 3, 4, 5],
            help="Your faction's consecutive weeks without winning Landsraad"
        )
        
        # Display bonus information
        bonus_multiplier = get_bonus_multiplier(weeks_lost)
        if weeks_lost > 0:
            st.info(f"🎯 Bonus: +{weeks_lost * 20}% points ({bonus_multiplier:.1f}x multiplier)")
        
        # Target points selector
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
            index=5  # Default to Complete Win
        )
        
        target_points = reward_targets[selected_reward]
        st.write(f"Target Points: **{target_points:,}**")
        
        st.divider()
        
        st.header("🔍 Item Search")
        
        # Get categories for filter
        categories = ["All Categories"] + get_categories()
        category_filter = st.selectbox("Filter by Category", categories)
        
        # Search field
        search_term = st.text_input("Search Items", placeholder="Type item name...")
        
        # Get items based on search
        if search_term:
            filtered_items = search_items(search_term, category_filter)
        else:
            filtered_items = all_items
            if category_filter != "All Categories":
                filtered_items = [item for item in all_items if item[1] == category_filter]
        
        # Item selection with session state integration
        if filtered_items:
            item_names = [item[0] for item in filtered_items]
            
            # Check if an item was selected via quick selector
            if "quick_selected_item" in st.session_state:
                # Use the quick-selected item and clear the flag
                selected_item_name = st.session_state.quick_selected_item
                del st.session_state.quick_selected_item
                
                # Find the index for the selectbox
                if selected_item_name in item_names:
                    default_index = item_names.index(selected_item_name)
                else:
                    default_index = 0
            else:
                # Use current selectbox selection or default
                default_index = 0
            
            selected_item_name = st.selectbox(
                "Select Item", 
                item_names, 
                index=default_index,
                key="item_selector"
            )
            
            # Update the global selected_item variable
            selected_item = get_item_by_name(selected_item_name)
            
            # Show selected item info in sidebar
            if selected_item:
                st.success(f"✅ **Selected:** {selected_item[0]}")
                st.write(f"**Category:** {selected_item[1]}")
                st.write(f"**Current Stock:** {selected_item[3]:,}")
        else:
            st.info("No items found")
            # Keep selected_item as None (already initialized)
        
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
    
    # Main interface - Item Details only
    st.header("📊 Item Details")
    
    if selected_item:
            name, category, points_per_item, current_stock = selected_item
            
            # Calculate effective points with bonus
            effective_points = get_effective_points(points_per_item, weeks_lost)
            bonus_multiplier = get_bonus_multiplier(weeks_lost)
            
            # Calculate required amounts
            required_amount = calculate_required_amount(points_per_item, target_points, weeks_lost)
            still_needed = max(0, required_amount - current_stock)
            completion_percentage = min(100, (current_stock / required_amount) * 100)
            
            # Display item info
            col2a, col2b = st.columns(2)
            
            with col2a:
                st.metric("Category", category)
                
                # Points display with bonus information
                if weeks_lost > 0:
                    st.metric(
                        "Points per Item", 
                        f"{points_per_item} → {effective_points:.1f}",
                        delta=f"{bonus_multiplier:.1f}x bonus"
                    )
                else:
                    st.metric("Points per Item", f"{points_per_item}")
                
                st.metric("Required Amount", f"{required_amount:,}")
            
            with col2b:
                st.metric("Still Needed", f"{still_needed:,}", 
                         delta=f"{-still_needed if still_needed == 0 else still_needed}")
                st.metric("Completion", f"{completion_percentage:.1f}%")
                
                # Progress bar
                st.progress(completion_percentage / 100)
            
            # Show target and effective calculation
            st.info(f"🎯 Target: **{selected_reward}** ({target_points:,} points)")
            
            # Editable stock field
            st.subheader("Update Stock")
            new_stock = st.number_input(
                "Current Stock", 
                min_value=0, 
                value=current_stock,
                key=f"stock_{name}"
            )
            
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
            
            # Status indicator with completion info
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
    
    # Overview table with view options
    st.header("📋 Inventory Overview")
    
    # View options
    multi_column_view = st.checkbox("Multi-Column View", value=False, help="Split table into multiple columns to see more items at once")
    
    if all_items:
        # Create overview dataframe
        overview_data = []
        for item in all_items:
            name, category, points_per_item, current_stock = item
            effective_points = get_effective_points(points_per_item, weeks_lost)
            required = calculate_required_amount(points_per_item, target_points, weeks_lost)
            needed = max(0, required - current_stock)
            completion = min(100, (current_stock / required) * 100)
            
            # Calculate completion status
            completions_achieved = current_stock // required
            items_for_next = required - (current_stock % required) if current_stock % required != 0 else 0
            
            if completions_achieved == 0:
                status = f"{needed:,} needed for #1"
            elif items_for_next == 0:
                status = f"{completions_achieved}x covered"
            else:
                status = f"{completions_achieved}x covered - {items_for_next:,} needed for #{completions_achieved + 1}"
            
            # Format points display
            if weeks_lost > 0:
                points_display = f"{points_per_item} → {effective_points:.1f}"
            else:
                points_display = str(points_per_item)
            
            if multi_column_view:
                # Compact view for multi-column display - remove points/item for more space
                overview_data.append({
                    "Item": name,
                    "Category": category,
                    "Stock": f"{current_stock:,}",
                    "Required": f"{required:,}",
                    "Status": status
                })
            else:
                # Full view with all columns
                overview_data.append({
                    "Item": name,
                    "Category": category,
                    "Points/Item": points_display,
                    "Current Stock": f"{current_stock:,}",
                    "Required": f"{required:,}",
                    "Still Needed": f"{needed:,}",
                    "Completion %": f"{completion:.1f}%",
                    "Status": status
                })
        
        df = pd.DataFrame(overview_data)
        
        # Add sorting functionality
        if not multi_column_view:
            # Show sorting options only in full view
            sort_col1, sort_col2 = st.columns([1, 3])
            with sort_col1:
                sort_by = st.selectbox("Sort by:", df.columns.tolist(), key="sort_selector")
            with sort_col2:
                ascending = st.checkbox("Ascending", value=True, key="sort_order")
            
            # Apply sorting with secondary sort by Item name
            if sort_by == "Item":
                # If sorting by Item, just sort by Item
                df = df.sort_values(by=sort_by, ascending=ascending)
            else:
                # If sorting by anything else, use Item as secondary sort
                df = df.sort_values(by=[sort_by, "Item"], ascending=[ascending, True])
        else:
            # In multi-column view, check if there's a previous sort state
            if "sort_selector" in st.session_state and "sort_order" in st.session_state:
                sort_by = st.session_state.sort_selector
                ascending = st.session_state.sort_order
                if sort_by in df.columns:
                    # Apply the same sorting logic as above
                    if sort_by == "Item":
                        df = df.sort_values(by=sort_by, ascending=ascending)
                        st.info(f"📊 Sorted by: **{sort_by}** ({'Ascending' if ascending else 'Descending'})")
                    else:
                        df = df.sort_values(by=[sort_by, "Item"], ascending=[ascending, True])
                        st.info(f"📊 Sorted by: **{sort_by}** ({'Ascending' if ascending else 'Descending'}), then by **Item** (Ascending)")
        
        if multi_column_view:
            # Split dataframe into multiple columns for better visibility
            num_items = len(df)
            items_per_column = max(10, num_items // 3)  # At least 10 items per column, max 3 columns
            
            if num_items <= 20:
                # Small dataset - use 2 columns
                mid_point = num_items // 2
                height = int(36.25 * (max(mid_point, num_items - mid_point) + 1))
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.subheader(f"Items 1-{mid_point}")
                    st.dataframe(df.iloc[:mid_point], use_container_width=True, hide_index=True, height=height)
                
                with col2:
                    st.subheader(f"Items {mid_point + 1}-{num_items}")
                    st.dataframe(df.iloc[mid_point:], use_container_width=True, hide_index=True, height=height)
                    
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
                    st.dataframe(df.iloc[:first_split], use_container_width=True, hide_index=True, height=height)
                
                with col2:
                    st.subheader(f"Items {first_split + 1}-{second_split}")
                    st.dataframe(df.iloc[first_split:second_split], use_container_width=True, hide_index=True, height=height)
                
                with col3:
                    st.subheader(f"Items {second_split + 1}-{num_items}")
                    st.dataframe(df.iloc[second_split:], use_container_width=True, hide_index=True, height=height)
        else:
            # Single table view - use data_editor to disable column sorting
            st.data_editor(
                df, 
                use_container_width=True, 
                hide_index=True,
                disabled=True,  # Disable editing to prevent interactions
                column_config={
                    col: st.column_config.TextColumn(col, disabled=True) 
                    for col in df.columns
                }
            )
        
        # Show clickable item list
        with st.expander("📋 Quick Item Selector", expanded=False):
            st.markdown("Click any item to select it in the main interface:")
            
            # Group items by category for easier browsing
            categories = {}
            for item in all_items:
                name, category, points_per_item, current_stock = item
                if category not in categories:
                    categories[category] = []
                categories[category].append(name)
            
            # Create columns for categories
            if categories:
                category_names = list(categories.keys())
                num_cols = min(3, len(category_names))
                cols = st.columns(num_cols)
                
                for idx, category in enumerate(category_names):
                    with cols[idx % num_cols]:
                        st.write(f"**{category}**")
                        for item_name in sorted(categories[category]):
                            if st.button(item_name, key=f"quick_select_{item_name}", use_container_width=True):
                                # Set the quick selection flag
                                st.session_state.quick_selected_item = item_name
                                st.rerun()
    
    # Statistics
    if all_items:
        st.header("📈 Statistics")
        
        total_items = len(all_items)
        completed_tasks = sum(1 for item in all_items if item[3] >= calculate_required_amount(item[2], target_points, weeks_lost))
        completion_rate = (completed_tasks / total_items) * 100 if total_items > 0 else 0
        
        stat_col1, stat_col2, stat_col3 = st.columns(3)
        
        with stat_col1:
            st.metric("Total Items", total_items)
        
        with stat_col2:
            st.metric("Completed Tasks", completed_tasks)
        
        with stat_col3:
            st.metric("Overall Completion", f"{completion_rate:.1f}%")

if __name__ == "__main__":
    main()
