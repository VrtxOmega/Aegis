const initTaskBoard = (aegis) => {
    const todoColumn = document.getElementById('todo-column');
    const inProgressColumn = document.getElementById('in-progress-column');
    const doneColumn = document.getElementById('done-column');
    const addTaskForm = document.getElementById('add-task-form');

    let draggedTask = null;

    const createTaskCard = (task) => {
        const card = document.createElement('div');
        card.className = 'task-card';
        card.setAttribute('draggable', 'true');
        card.dataset.taskId = task.id;
        card.dataset.status = task.status;
        card.innerHTML = `
            <strong>${task.title}</strong><br>
            <small>Assigned to: ${task.assigned_to || 'Unassigned'}</small>
        `;

        card.addEventListener('dragstart', () => {
            draggedTask = card;
            setTimeout(() => card.classList.add('dragging'), 0);
        });

        card.addEventListener('dragend', () => {
            draggedTask.classList.remove('dragging');
            draggedTask = null;
        });

        return card;
    };

    const addDropListeners = (column) => {
        column.addEventListener('dragover', (e) => {
            e.preventDefault(); // Allow drop
        });

        column.addEventListener('drop', async (e) => {
            e.preventDefault();
            if (draggedTask) {
                const taskId = draggedTask.dataset.taskId;
                const newStatus = column.id.replace('-column', '').replace('-', ' '); // 'todo-column' -> 'To Do'
                
                // Update UI immediately for responsiveness
                column.appendChild(draggedTask);
                draggedTask.dataset.status = newStatus;

                // Update backend
                const result = await aegis.updateTask(taskId, { status: newStatus });
                if (result.error) {
                    console.error('Error updating task status:', result.error);
                    // Optionally revert UI if backend update fails
                }
            }
        });
    };

    addDropListeners(todoColumn);
    addDropListeners(inProgressColumn);
    addDropListeners(doneColumn);

    const loadTasks = async () => {
        todoColumn.querySelectorAll('.task-card').forEach(card => card.remove());
        inProgressColumn.querySelectorAll('.task-card').forEach(card => card.remove());
        doneColumn.querySelectorAll('.task-card').forEach(card => card.remove());

        const tasks = await aegis.getTasks();
        if (tasks.error) {
            console.error('Tasks Error:', tasks.error);
            todoColumn.innerHTML += `<p class="error-message\