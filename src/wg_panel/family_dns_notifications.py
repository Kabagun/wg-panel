"""Administrator notifications for explicit user DNS-exception proposals."""
from .core import DOMAIN
from .telegram import send_telegram_sync, submit_background


def notify_request(record):
    """Queue at most one initial notification per newly created proposal."""
    text = (
        '🛡️ Заявка на разблокировку сайта\n\n'
        f"Пользователь: {record['username']}\nСайт: {record['domain']}\n"
        f"Комментарий: {record['reason'] or 'Не указан'}\n\n"
        'Одобрение разрешит домен и его поддомены для всех с семейной защитой.'
    )
    buttons = [[
        {'text': '✅ Одобрить', 'callback_data': f"dns:approve:{record['id']}"},
        {'text': '❌ Отклонить', 'callback_data': f"dns:reject:{record['id']}"},
    ]]
    if DOMAIN != 'localhost':
        buttons.append([{'text': 'Открыть заявки', 'url': f'https://{DOMAIN}/admin/family-dns'}])
    return submit_background(send_telegram_sync, text, True, None, buttons)
