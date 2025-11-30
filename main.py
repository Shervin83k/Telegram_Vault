import asyncio
import logging
from aiogram import Bot, Dispatcher
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram import BaseMiddleware
from aiogram.types import Update
from aiogram.fsm.context import FSMContext

from config import BOT_TOKEN
from utils.logger import setup_logger
from utils.session_manager import sessions as session_manager
from handlers import auth, main_menu, password_entry

# Setup logging
setup_logger()
logger = logging.getLogger(__name__)


class SessionMiddleware(BaseMiddleware):
    """Middleware for session management and activity tracking."""
    
    def __init__(self):
        super().__init__()

    async def __call__(self, handler, event, data):
        """Process incoming updates with session management."""
        user_id = None
        if event.message:
            user_id = event.message.from_user.id
        elif event.callback_query:
            user_id = event.callback_query.from_user.id
        
        if user_id:
            session_manager.update_user_activity(user_id)
            
            state: FSMContext = data.get('state')
            if state:
                is_authenticated = session_manager.is_session_valid(user_id)
                
                if is_authenticated and not session_manager.is_session_valid(user_id):
                    logger.info(f"Session expired for user {user_id}")
                    if event.message:
                        await event.message.answer(
                            "Session expired due to inactivity. Please use /start to begin again.",
                            reply_markup=None
                        )
                    elif event.callback_query:
                        await event.callback_query.message.answer(
                            "Session expired due to inactivity. Please use /start to begin again.",
                            reply_markup=None
                        )
                    await state.clear()
                    return
        
        return await handler(event, data)


async def session_cleanup_task():
    """Background task to clean up expired sessions."""
    while True:
        try:
            session_manager.cleanup_expired_sessions()
            await asyncio.sleep(30)
        except Exception as e:
            logger.error(f"Session cleanup error: {e}")
            await asyncio.sleep(30)


async def main():
    """Main application entry point."""
    try:
        bot = Bot(token=BOT_TOKEN)
        storage = MemoryStorage()
        dp = Dispatcher(storage=storage)
        
        session_middleware = SessionMiddleware()
        dp.update.middleware(session_middleware)
        
        dp.include_router(auth.auth_router)
        dp.include_router(main_menu.router)
        dp.include_router(password_entry.password_router)
        
        asyncio.create_task(session_cleanup_task())
        
        logger.info("Bot starting up...")
        await dp.start_polling(bot)
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        if 'bot' in locals():
            await bot.session.close()
        logger.info("Bot shut down successfully")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Bot stopped by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")