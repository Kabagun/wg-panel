"""Administrator notifications for explicit user DNS-exception proposals."""
from .core import DOMAIN
from .telegram import send_telegram_sync, submit_background


def notify_request(record, *, kind='dns'):
    """Queue at most one initial notification per newly created proposal."""
    if kind not in {'dns', 'smart'}:
        raise ValueError('Invalid proposal kind')
    text = (
        ('🧠 Заявка в Умный VPN\n\n' if kind == 'smart'
         else '🛡️ Заявка на разблокировку сайта\n\n') +
        f"Пользователь: {record['username']}\nСайт: {record['domain']}\n"
        f"Комментарий: {record['reason'] or 'Не указан'}\n\n" +
        ('Одобрение добавит домен в общий список Умного VPN. Семейный DNS не изменится.'
         if kind == 'smart' else
         'Одобрение разрешит домен и его поддомены для всех с семейной защитой.')
    )
    prefix = 'smart' if kind == 'smart' else 'dns'
    buttons = [[
        {'text': '✅ Одобрить', 'callback_data': f"{prefix}:approve:{record['id']}"},
        {'text': '❌ Отклонить', 'callback_data': f"{prefix}:reject:{record['id']}"},
    ]]
    if DOMAIN != 'localhost':
        page = '/admin/happ-rules' if kind == 'smart' else '/admin/family-dns'
        buttons.append([{'text': 'Открыть заявки', 'url': f'https://{DOMAIN}' + page}])
    return submit_background(send_telegram_sync, text, True, None, buttons)
