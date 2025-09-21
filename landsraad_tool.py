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

    # Sidebar for item management and settings
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

    # Main interface
    col1, col2 = st.columns([1, 2])

    with col1:
        st.header("🔍 Item Search")

        # Get categories for filter
        categories = ["All Categories"] + get_categories()
        category_filter = st.selectbox("Filter by Category", categories)

        # Search field
        search_term = st.text_input("Search Items", placeholder="Type item name...")

        # Get items based on search
        if search_term:
            items = search_items(search_term, category_filter)
        else:
            items = get_all_items()
            if category_filter != "All Categories":
                items = [item for item in items if item[1] == category_filter]

        # Item selection with session state integration
        if items:
            item_names = [item[0] for item in items]

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

            selected_item = get_item_by_name(selected_item_name)
        else:
            st.info("No items found")
            selected_item = None

    with col2:
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

    # Overview table
    st.header("📋 Inventory Overview")

    if items:
        # Create overview dataframe
        overview_data = []
        for item in items:
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

        # Remove the problematic data_editor approach and use simpler clickable method
        df = pd.DataFrame(overview_data)
        st.dataframe(df, use_container_width=True, hide_index=True)

        # Show clickable item list
        with st.expander("📋 Quick Item Selector", expanded=False):
            st.markdown("Click any item to select it in the main interface:")

            # Group items by category for easier browsing
            categories = {}
            for item in items:
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
    if items:
        st.header("📈 Statistics")

        total_items = len(items)
        completed_tasks = sum(1 for item in items if item[3] >= calculate_required_amount(item[2], target_points, weeks_lost))
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
