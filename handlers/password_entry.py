from aiogram import Router, F
from aiogram.types import Message, CallbackQuery, ReplyKeyboardRemove
from aiogram.filters import StateFilter, Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.utils.keyboard import InlineKeyboardBuilder
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, ReplyKeyboardMarkup, KeyboardButton
from handlers.main_menu import get_main_menu_keyboard
import logging

from db.database import db
from utils.encryption import encrypt_data, decrypt_data
from utils.logger import logger
from utils.session_manager import sessions
from utils.validators import InputValidator

password_router = Router()


class PasswordState(StatesGroup):
    """State machine for password entry management flows."""
    waiting_for_entry_name = State()
    waiting_for_email = State()
    waiting_for_password = State()
    waiting_for_encryption_key = State()
    waiting_for_new_email = State()
    waiting_for_new_password = State()
    waiting_for_new_name = State()


def get_cancel_keyboard():
    """Return cancellation keyboard for interruptible operations."""
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text="❌ Cancel")]],
        resize_keyboard=True,
        one_time_keyboard=True
    )


@password_router.message(F.text == "❌ Cancel")
@password_router.message(Command("cancel"))
async def cancel_password_operation(message: Message, state: FSMContext):
    """Cancel ongoing password operation and return to main menu."""
    await state.clear()
    await message.answer(
        "🔄 Operation cancelled. Returning to main menu.",
        reply_markup=get_main_menu_keyboard()
    )


@password_router.message(F.text == "➕ Add new entry")
async def add_new_entry(message: Message, state: FSMContext):
    """Initiate new password entry creation process."""
    try:
        user_id = message.from_user.id
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await message.answer("❌ Please log in first using /start")
            return
        
        await message.answer(
            "📝 Create New Password Entry\n\n"
            "Please enter a name for this entry (e.g., 'Gmail', 'Facebook'):\n\n"
            "Use 'Cancel' or /cancel to return to main menu",
            reply_markup=get_cancel_keyboard()
        )
        await state.set_state(PasswordState.waiting_for_entry_name)
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "add_new_entry")
        await message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.message(PasswordState.waiting_for_entry_name)
async def process_entry_name(message: Message, state: FSMContext):
    """Process entry name input and request email/username."""
    try:
        entry_name = message.text.strip()
        
        if entry_name.lower() in ['cancel', 'back']:
            await cancel_password_operation(message, state)
            return
        
        is_valid, error_msg = InputValidator.validate_entry_name(entry_name)
        if not is_valid:
            await message.answer(f"🔸 {error_msg}\n\nPlease enter a valid entry name:")
            return
        
        await state.update_data(entry_name=entry_name)
        await message.answer(
            f"📧 Now enter the email or username for {entry_name}:\n\n"
            "Use 'Cancel' or /cancel to return to main menu",
            reply_markup=get_cancel_keyboard()
        )
        await state.set_state(PasswordState.waiting_for_email)
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "process_entry_name")
        await message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.message(PasswordState.waiting_for_email)
async def process_new_email(message: Message, state: FSMContext):
    """Process email/username input and request password."""
    try:
        user_id = message.from_user.id
        data = await state.get_data()
        entry_name = data.get('entry_name')
        email_input = message.text.strip()
        
        if email_input.lower() in ['cancel', 'back']:
            await cancel_password_operation(message, state)
            return
        
        is_valid, error_msg = InputValidator.validate_email_or_username(email_input)
        if not is_valid:
            await message.answer(f"🔸 {error_msg}\n\nPlease enter a valid email or username:")
            return
        
        await state.update_data(email=email_input)
        
        await message.answer(
            f"🔑 Now enter the password for {entry_name}:\n\n"
            "Use 'Cancel' or /cancel to return to main menu",
            reply_markup=get_cancel_keyboard()
        )
        
        await state.set_state(PasswordState.waiting_for_password)
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "process_new_email")
        await message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.message(PasswordState.waiting_for_password)
async def process_password(message: Message, state: FSMContext):
    """Process password input and save encrypted entry to database."""
    try:
        user_id = message.from_user.id
        password_input = message.text.strip()
        
        if password_input.lower() in ['cancel', 'back']:
            await cancel_password_operation(message, state)
            return
        
        is_valid, error_msg = InputValidator.validate_password_length(password_input)
        if not is_valid:
            await message.answer(f"🔸 {error_msg}\n\nPlease enter a valid password:")
            return
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await message.answer("❌ User not found. Please log in again using /start")
            return
        
        data = await state.get_data()
        entry_name = data.get('entry_name')
        email_input = data.get('email')
        encryption_key = user_data['encryption_key']
        
        encrypted_email = encrypt_data(email_input, encryption_key)
        encrypted_password = encrypt_data(password_input, encryption_key)
        
        success = db.create_password_entry(
            user_id=user_data['id'],
            entry_name=entry_name,
            email=encrypted_email,
            password=encrypted_password
        )
        
        if success:
            await message.answer(
                f"✅ Password entry saved successfully!\n\n📝 Entry: {entry_name}",
                reply_markup=get_main_menu_keyboard()
            )
        else:
            await message.answer(
                "❌ Failed to save password entry. Please try again.",
                reply_markup=get_main_menu_keyboard()
            )
        
        await state.clear()
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "process_password")
        await message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.message(F.text == "📋 List my entries")
async def list_entries(message: Message, state: FSMContext):
    """Display all password entries for the authenticated user."""
    try:
        user_id = message.from_user.id
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await message.answer("❌ Please log in first using /start")
            return
        
        entries = db.get_password_entries(user_data['id'])
        
        if not entries:
            await message.answer(
                "📝 No password entries found.\n\nUse '➕ Add new entry' to create your first entry.",
                reply_markup=get_main_menu_keyboard()
            )
            return
        
        builder = InlineKeyboardBuilder()
        for entry in entries:
            builder.button(
                text=f"📁 {entry['entry_name']}",
                callback_data=f"view_entry:{entry['id']}"
            )
        
        builder.button(text="🔙 Back to Main Menu", callback_data="back_to_main")
        builder.adjust(1)
        
        await message.answer(
            "📋 Your Password Entries:\n\nSelect an entry to view details:",
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "list_entries")
        await message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.callback_query(F.data.startswith("view_entry:"))
async def view_password_entry(callback: CallbackQuery, state: FSMContext):
    """Display detailed view and management options for a specific entry."""
    try:
        user_id = callback.from_user.id
        entry_id = int(callback.data.split(":")[1])
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await callback.message.edit_text("❌ User not found. Please log in again.")
            return
        
        entry = db.get_password_entry(entry_id, user_data['id'])
        if not entry:
            await callback.message.edit_text("❌ Entry not found.")
            return
        
        await state.update_data(current_entry_id=entry_id)
        
        builder = InlineKeyboardBuilder()
        builder.button(text="🔐 Show Encrypted", callback_data="show_encrypted")
        builder.button(text="🔓 Decrypt Entry", callback_data="decrypt_entry")
        builder.button(text="✏️ Edit Entry", callback_data="edit_entry")
        builder.button(text="🗑️ Remove Entry", callback_data="remove_entry")
        builder.button(text="🔙 Back to List", callback_data="list_entries")
        builder.adjust(2, 2, 1)
        
        await callback.message.edit_text(
            f"📁 Entry: {entry['entry_name']}\n\nSelect an action:",
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "view_password_entry")
        await callback.message.edit_text(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.callback_query(F.data == "show_encrypted")
async def show_encrypted_data(callback: CallbackQuery, state: FSMContext):
    """Display encrypted data for the selected entry."""
    try:
        user_id = callback.from_user.id
        data = await state.get_data()
        entry_id = data.get('current_entry_id')
        
        if not entry_id:
            await callback.message.edit_text("❌ Entry not found. Please select an entry again.")
            return
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await callback.message.edit_text("❌ User not found. Please log in again.")
            return
        
        entry = db.get_password_entry(entry_id, user_data['id'])
        if not entry:
            await callback.message.edit_text("❌ Entry not found.")
            return
        
        await callback.message.edit_text(
            f"🔐 Encrypted Data for: {entry['entry_name']}\n\n"
            f"📧 Email: {entry['email']}\n"
            f"🔑 Password: {entry['password']}\n\n"
            "This is the encrypted data as stored in the database.",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="🔙 Back to Entry", callback_data=f"view_entry:{entry_id}")
            ]])
        )
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "show_encrypted_data")
        await callback.message.edit_text(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.callback_query(F.data == "decrypt_entry")
async def ask_encryption_key(callback: CallbackQuery, state: FSMContext):
    """Request encryption key for entry decryption."""
    try:
        data = await state.get_data()
        entry_id = data.get('current_entry_id')
        
        if not entry_id:
            await callback.message.edit_text("❌ Entry not found. Please select an entry again.")
            return
            
        await callback.message.edit_text(
            "🔑 To decrypt this entry, please enter your encryption key:\n\n"
            "Use 'Cancel' or /cancel to return to main menu"
        )
        await state.set_state(PasswordState.waiting_for_encryption_key)
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "ask_encryption_key")
        await callback.message.edit_text(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.message(PasswordState.waiting_for_encryption_key)
async def decrypt_with_key(message: Message, state: FSMContext):
    """Decrypt and display entry data using provided encryption key."""
    try:
        user_id = message.from_user.id
        encryption_key = message.text.strip()
        
        if encryption_key.lower() in ['cancel', 'back']:
            await cancel_password_operation(message, state)
            return
        
        data = await state.get_data()
        entry_id = data.get('current_entry_id')
        
        if not entry_id:
            await message.answer("❌ Entry not found. Please select an entry again.")
            return
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await message.answer("❌ User not found. Please log in again.")
            return
        
        entry = db.get_password_entry(entry_id, user_data['id'])
        if not entry:
            await message.answer("❌ Entry not found.")
            return
        
        try:
            decrypted_email = decrypt_data(entry['email'], encryption_key)
            decrypted_password = decrypt_data(entry['password'], encryption_key)
            
            await message.answer(
                f"🔓 Decrypted Data for: {entry['entry_name']}\n\n"
                f"📧 Email/Username: {decrypted_email}\n"
                f"🔑 Password: {decrypted_password}",
                reply_markup=ReplyKeyboardRemove()
            )
            
            await view_password_entry_after_decrypt(message, entry_id)
            
        except Exception:
            await message.answer(
                "❌ Invalid encryption key. Please try again.",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                    InlineKeyboardButton(text="🔙 Back to Entry", callback_data=f"view_entry:{entry_id}")
                ]])
            )
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "decrypt_with_key")
        await message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.callback_query(F.data == "edit_entry")
async def edit_entry_menu(callback: CallbackQuery, state: FSMContext):
    """Display edit options for the selected entry."""
    try:
        user_id = callback.from_user.id
        data = await state.get_data()
        entry_id = data.get('current_entry_id')
        
        if not entry_id:
            await callback.message.edit_text("❌ Entry not found. Please select an entry again.")
            return
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await callback.message.edit_text("❌ User not found. Please log in again.")
            return
        
        entry = db.get_password_entry(entry_id, user_data['id'])
        if not entry:
            await callback.message.edit_text("❌ Entry not found.")
            return
        
        builder = InlineKeyboardBuilder()
        builder.button(text="📧 Edit Email", callback_data="edit_email")
        builder.button(text="🔑 Edit Password", callback_data="edit_password")
        builder.button(text="📝 Edit Name", callback_data="edit_name")
        builder.button(text="🔙 Back to Entry", callback_data=f"view_entry:{entry_id}")
        builder.adjust(1)
        
        await callback.message.edit_text(
            f"✏️ Editing: {entry['entry_name']}\n\nSelect field to edit:",
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "edit_entry_menu")
        await callback.message.edit_text(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.callback_query(F.data == "edit_email")
async def start_edit_email(callback: CallbackQuery, state: FSMContext):
    """Initiate email editing process."""
    try:
        user_id = callback.from_user.id
        data = await state.get_data()
        entry_id = data.get('current_entry_id')
        
        if not entry_id:
            await callback.message.edit_text("❌ Entry not found. Please select an entry again.")
            return
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await callback.message.edit_text("❌ User not found. Please log in again.")
            return
        
        await state.update_data(
            editing_entry_id=entry_id,
            encryption_key=user_data['encryption_key']
        )
        
        await callback.message.edit_text(
            "📧 Please enter the new email or username:\n\n"
            "Use 'Cancel' or /cancel to return to main menu"
        )
        await state.set_state(PasswordState.waiting_for_new_email)
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "start_edit_email")
        await callback.message.edit_text(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.message(PasswordState.waiting_for_new_email)
async def process_new_email_edit(message: Message, state: FSMContext):
    """Process and save updated email/username."""
    try:
        user_id = message.from_user.id
        data = await state.get_data()
        entry_id = data.get('editing_entry_id')
        encryption_key = data.get('encryption_key')
        new_email = message.text.strip()
        
        if new_email.lower() in ['cancel', 'back']:
            await cancel_password_operation(message, state)
            return
        
        is_valid, error_msg = InputValidator.validate_email_or_username(new_email)
        if not is_valid:
            await message.answer(f"🔸 {error_msg}\n\nPlease enter a valid email or username:")
            return
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await message.answer("❌ User not found. Please log in again.")
            return
        
        encrypted_email = encrypt_data(new_email, encryption_key)
        success = db.update_password_entry(entry_id, user_data['id'], {'email': encrypted_email})
        
        if success:
            await message.answer(
                "✅ Email updated successfully!",
                reply_markup=ReplyKeyboardRemove()
            )
            await view_password_entry_after_edit(message, entry_id)
        else:
            await message.answer(
                "❌ Failed to update email. Please try again.",
                reply_markup=ReplyKeyboardRemove()
            )
            
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "process_new_email_edit")
        await message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.callback_query(F.data == "edit_password")
async def start_edit_password(callback: CallbackQuery, state: FSMContext):
    """Initiate password editing process."""
    try:
        user_id = callback.from_user.id
        data = await state.get_data()
        entry_id = data.get('current_entry_id')
        
        if not entry_id:
            await callback.message.edit_text("❌ Entry not found. Please select an entry again.")
            return
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await callback.message.edit_text("❌ User not found. Please log in again.")
            return
        
        await state.update_data(
            editing_entry_id=entry_id,
            encryption_key=user_data['encryption_key']
        )
        
        await callback.message.edit_text(
            "🔑 Please enter the new password:\n\n"
            "Use 'Cancel' or /cancel to return to main menu"
        )
        await state.set_state(PasswordState.waiting_for_new_password)
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "start_edit_password")
        await callback.message.edit_text(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.message(PasswordState.waiting_for_new_password)
async def process_new_password_edit(message: Message, state: FSMContext):
    """Process and save updated password."""
    try:
        user_id = message.from_user.id
        data = await state.get_data()
        entry_id = data.get('editing_entry_id')
        encryption_key = data.get('encryption_key')
        new_password = message.text.strip()
        
        if new_password.lower() in ['cancel', 'back']:
            await cancel_password_operation(message, state)
            return
        
        is_valid, error_msg = InputValidator.validate_password_length(new_password)
        if not is_valid:
            await message.answer(f"🔸 {error_msg}\n\nPlease enter a valid password:")
            return
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await message.answer("❌ User not found. Please log in again.")
            return
        
        encrypted_password = encrypt_data(new_password, encryption_key)
        success = db.update_password_entry(entry_id, user_data['id'], {'password': encrypted_password})
        
        if success:
            await message.answer(
                "✅ Password updated successfully!",
                reply_markup=ReplyKeyboardRemove()
            )
            await view_password_entry_after_edit(message, entry_id)
        else:
            await message.answer(
                "❌ Failed to update password. Please try again.",
                reply_markup=ReplyKeyboardRemove()
            )
            
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "process_new_password_edit")
        await message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.callback_query(F.data == "edit_name")
async def start_edit_name(callback: CallbackQuery, state: FSMContext):
    """Initiate entry name editing process."""
    try:
        user_id = callback.from_user.id
        data = await state.get_data()
        entry_id = data.get('current_entry_id')
        
        if not entry_id:
            await callback.message.edit_text("❌ Entry not found. Please select an entry again.")
            return
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await callback.message.edit_text("❌ User not found. Please log in again.")
            return
        
        await state.update_data(editing_entry_id=entry_id)
        await callback.message.edit_text(
            "📝 Please enter the new entry name:\n\n"
            "Use 'Cancel' or /cancel to return to main menu"
        )
        await state.set_state(PasswordState.waiting_for_new_name)
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "start_edit_name")
        await callback.message.edit_text(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.message(PasswordState.waiting_for_new_name)
async def process_new_name_edit(message: Message, state: FSMContext):
    """Process and save updated entry name."""
    try:
        user_id = message.from_user.id
        data = await state.get_data()
        entry_id = data.get('editing_entry_id')
        new_name = message.text.strip()
        
        if new_name.lower() in ['cancel', 'back']:
            await cancel_password_operation(message, state)
            return
        
        is_valid, error_msg = InputValidator.validate_entry_name(new_name)
        if not is_valid:
            await message.answer(f"🔸 {error_msg}\n\nPlease enter a valid entry name:")
            return
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await message.answer("❌ User not found. Please log in again.")
            return
        
        success = db.update_password_entry(entry_id, user_data['id'], {'entry_name': new_name})
        
        if success:
            await message.answer(
                "✅ Entry name updated successfully!",
                reply_markup=ReplyKeyboardRemove()
            )
            await view_password_entry_after_edit(message, entry_id)
        else:
            await message.answer(
                "❌ Failed to update entry name. Please try again.",
                reply_markup=ReplyKeyboardRemove()
            )
            
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "process_new_name_edit")
        await message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.callback_query(F.data == "remove_entry")
async def confirm_remove_entry(callback: CallbackQuery, state: FSMContext):
    """Request confirmation for entry deletion."""
    try:
        user_id = callback.from_user.id
        data = await state.get_data()
        entry_id = data.get('current_entry_id')
        
        if not entry_id:
            await callback.message.edit_text("❌ Entry not found. Please select an entry again.")
            return
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await callback.message.edit_text("❌ User not found. Please log in again.")
            return
        
        builder = InlineKeyboardBuilder()
        builder.button(text="✅ Confirm Delete", callback_data=f"confirm_remove:{entry_id}")
        builder.button(text="❌ Cancel", callback_data=f"view_entry:{entry_id}")
        builder.adjust(2)
        
        await callback.message.edit_text(
            "🗑️ Confirm Entry Deletion\n\n"
            "⚠️ This action cannot be undone!",
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "confirm_remove_entry")
        await callback.message.edit_text(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.callback_query(F.data.startswith("confirm_remove:"))
async def perform_remove_entry(callback: CallbackQuery, state: FSMContext):
    """Execute entry deletion after confirmation."""
    try:
        user_id = callback.from_user.id
        entry_id = int(callback.data.split(':')[1])
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await callback.message.edit_text("❌ User not found. Please log in again.")
            return
        
        success = db.delete_password_entry(entry_id, user_data['id'])
        
        if success:
            remaining_entries = db.get_password_entries(user_data['id'])
            
            if not remaining_entries:
                await callback.message.edit_text(
                    "✅ Password entry deleted successfully!\n\nNo password entries remaining.",
                    reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                        InlineKeyboardButton(text="➕ Add new entry", callback_data="add_new_entry_callback"),
                        InlineKeyboardButton(text="📱 Main Menu", callback_data="back_to_main")
                    ]])
                )
            else:
                await callback.message.edit_text(
                    "✅ Password entry deleted successfully!",
                    reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                        InlineKeyboardButton(text="📋 Back to entries", callback_data="list_entries")
                    ]])
                )
        else:
            await callback.message.edit_text(
                "❌ Failed to delete password entry. Please try again.",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                    InlineKeyboardButton(text="📋 Back to entries", callback_data="list_entries")
                ]])
            )
            
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "perform_remove_entry")
        await callback.message.edit_text(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again."
        )


@password_router.callback_query(F.data == "list_entries")
async def back_to_list(callback: CallbackQuery, state: FSMContext):
    """Navigate back to entries list view."""
    try:
        user_id = callback.from_user.id
        
        session_data = sessions.get_user_data(user_id)
        username = session_data.get('username')
        user_data = db.get_user_by_username(username)
        
        if not user_data:
            await callback.message.edit_text("❌ Please log in first using /start")
            return
        
        entries = db.get_password_entries(user_data['id'])
        
        if not entries:
            await callback.message.answer(
                "📝 No password entries found.\n\nUse '➕ Add new entry' to create your first entry.",
                reply_markup=get_main_menu_keyboard()
            )
            return
        
        builder = InlineKeyboardBuilder()
        for entry in entries:
            builder.button(
                text=f"📁 {entry['entry_name']}",
                callback_data=f"view_entry:{entry['id']}"
            )
        
        builder.button(text="🔙 Back to Main Menu", callback_data="back_to_main")
        builder.adjust(1)
        
        await callback.message.edit_text(
            "📋 Your Password Entries:\n\nSelect an entry to view details:",
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "back_to_list")
        await callback.message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again.",
            reply_markup=get_main_menu_keyboard()
        )


@password_router.callback_query(F.data == "back_to_main")
async def back_to_main_menu(callback: CallbackQuery, state: FSMContext):
    """Navigate back to main menu."""
    try:
        await callback.message.edit_text("📱 Main Menu", reply_markup=None)
        await callback.message.answer(
            "📱 Main Menu",
            reply_markup=get_main_menu_keyboard()
        )
        await callback.answer()
    except Exception as e:
        error_id = logger.log_unexpected_error(e, "back_to_main_menu")
        await callback.message.answer(
            f"⚠️ An unexpected error occurred. Reference: {error_id}\nPlease use /start to begin again.",
            reply_markup=get_main_menu_keyboard()
        )


@password_router.callback_query(F.data == "add_new_entry_callback")
async def add_new_entry_callback(callback: CallbackQuery, state: FSMContext):
    """Initiate new entry creation from callback."""
    await add_new_entry(callback.message, state)


async def view_password_entry_after_decrypt(message: Message, entry_id: int):
    """Display entry management options after decryption."""
    builder = InlineKeyboardBuilder()
    builder.button(text="🔐 Show Encrypted", callback_data="show_encrypted")
    builder.button(text="🔓 Decrypt Entry", callback_data="decrypt_entry")
    builder.button(text="✏️ Edit Entry", callback_data="edit_entry")
    builder.button(text="🗑️ Remove Entry", callback_data="remove_entry")
    builder.button(text="🔙 Back to List", callback_data="list_entries")
    builder.adjust(2, 2, 1)
    
    await message.answer("Select an action:", reply_markup=builder.as_markup())


async def view_password_entry_after_edit(message: Message, entry_id: int):
    """Display entry management options after editing."""
    builder = InlineKeyboardBuilder()
    builder.button(text="🔐 Show Encrypted", callback_data="show_encrypted")
    builder.button(text="🔓 Decrypt Entry", callback_data="decrypt_entry")
    builder.button(text="✏️ Edit Entry", callback_data="edit_entry")
    builder.button(text="🗑️ Remove Entry", callback_data="remove_entry")
    builder.button(text="🔙 Back to List", callback_data="list_entries")
    builder.adjust(2, 2, 1)
    
    await message.answer("Select an action:", reply_markup=builder.as_markup())