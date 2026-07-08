async function fetchUnreadNotifications() {
    try {
        const res = await fetch('/api/notifications/unread');
        const data = await res.json();
        if (!data.success) {
            return;
        }

        const badge = document.getElementById('notif-badge');
        const list = document.getElementById('notif-list');
        if (!badge || !list) {
            return;
        }

        if (data.notifications && data.notifications.length > 0) {
            badge.style.display = 'block';
            list.innerHTML = data.notifications.map((n) => `
                <div class="p-3 border-b border-white/5 hover:bg-white/5 cursor-pointer notif-item" data-notif-id="${n.id}">
                    <p class="text-xs text-slate-300 font-medium">${n.message}</p>
                    <p class="text-[10px] text-slate-500 mt-1">${n.timestamp}</p>
                </div>
            `).join('');
        } else {
            badge.style.display = 'none';
            list.innerHTML = '<div class="p-4 text-center text-xs text-slate-500">No new notifications</div>';
        }
    } catch (error) {
        console.error('Error fetching notifications:', error);
    }
}

async function markRead(id) {
    try {
        const res = await fetch(`/api/notifications/${id}/read`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            fetchUnreadNotifications();
        }
    } catch (error) {
        console.error('Error marking notification as read:', error);
    }
}

document.addEventListener('DOMContentLoaded', function () {
    const sidebarToggle = document.getElementById('sidebar-toggle');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', function () {
            const sidebar = document.getElementById('sidebar');
            if (sidebar) {
                sidebar.classList.toggle('-translate-x-full');
            }
        });
    }

    const notifList = document.getElementById('notif-list');
    if (notifList) {
        notifList.addEventListener('click', function (event) {
            const item = event.target.closest('.notif-item');
            if (!item) {
                return;
            }
            const notifId = item.getAttribute('data-notif-id');
            if (notifId) {
                markRead(notifId);
            }
        });
    }

    fetchUnreadNotifications();
    setInterval(fetchUnreadNotifications, 8000);
});
