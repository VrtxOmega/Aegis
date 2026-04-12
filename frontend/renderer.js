document.addEventListener('DOMContentLoaded', () => {
    const systemStatusCpu = document.getElementById('cpu-usage').querySelector('.value');
    const systemStatusRam = document.getElementById('ram-usage').querySelector('.value');
    const systemStatusDisk = document.getElementById('disk-usage').querySelector('.value');
    const projectListDiv = document.getElementById('project-list');
    const todoTasksDiv = document.getElementById('todo-tasks');
    const inProgressTasksDiv = document.getElementById('in-progress-tasks');
    const doneTasksDiv = document.getElementById('done-tasks');
    const weatherDisplayDiv = document.getElementById('weather-display');

    // --- System Status ---
    async function updateSystemStatus() {
        const status = await window.aegis.getSystemStatus();
        if (status && !status.error) {
            systemStatusCpu.textContent = `${status.cpu.toFixed(1)}%`;
            systemStatusRam.textContent = `${status.memory.used.toFixed(1)} GB / ${status.memory.total.toFixed(1)} GB`;
            systemStatusDisk.textContent = `${status.disk.used.toFixed(1)} GB / ${status.disk.total.toFixed(1)} GB`;
            systemStatusDiskPressure.textContent = status.disk_pressure || '--';
        } else {
            console.error('Failed to fetch system status:', status.error);
            systemStatusCpu.textContent = 'Error';
            systemStatusRam.textContent = 'Error';
            systemStatusDisk.textContent = 'Error';
        }
    }
    setInterval(updateSystemStatus, 5000); // Refresh every 5 seconds
    updateSystemStatus(); // Initial fetch

    // --- Project Launcher ---
    async function updateProjectList() {
        const projects = await window.aegis.getProjects();
        projectListDiv.innerHTML = ''; // Clear previous list
        if (projects && !projects.error && projects.length > 0) {
            projects.forEach(project => {
                const projectCard = document.createElement('div');
                projectCard.className = 'project-card';
                projectCard.innerHTML = `
                    <h3>${project.name}</h3>
                    <p>${project.path}</p>
                    <button class="open-folder-btn" data-path="${project.path}">Open Folder</button>
                `;
                projectListDiv.appendChild(projectCard);
            });
            projectListDiv.querySelectorAll('.open-folder-btn').forEach(button => {
                button.addEventListener('click', (event) => {
                    const projectPath = event.target.dataset.path;
                    window.aegis.openProjectFolder(projectPath);
                });
            });
        } else if (projects.error) {
            projectListDiv.innerHTML = `<p class="error-text">Failed to load projects: ${projects.error}</p>`;
        } else {
            projectListDiv.innerHTML = '<p class="no-data-text">No projects found.</p>';
        }
    }
    updateProjectList();

    // --- Family Task Board ---
    async function updateTaskBoard() {
        const tasks = await window.aegis.getTasks();
        todoTasksDiv.innerHTML = '';
        inProgressTasksDiv.innerHTML = '';
        doneTasksDiv.innerHTML = '';

        if (tasks && !tasks.error && tasks.length > 0) {
            tasks.forEach(task => {
                const taskCard = document.createElement('div');
                taskCard.className = 'task-card';
                taskCard.setAttribute('draggable', 'true');
                taskCard.dataset.taskId = task.id;
                taskCard.dataset.taskStatus = task.status;
                taskCard.innerHTML = `
                    <h4>${task.description}</h4>
                    <p>Assigned to: ${task.assignee}</p>
                    <div class="task-actions">
                        <button class="delete-task-btn" data-id="${task.id}">Delete</button>
                    </div>
                `;

                if (task.status === 'To Do') {
                    todoTasksDiv.appendChild(taskCard);
                } else if (task.status === 'In Progress') {
                    inProgressTasksDiv.appendChild(taskCard);
                } else if (task.status === 'Done') {
                    doneTasksDiv.appendChild(taskCard);
                }
            });

            // Add drag and drop listeners
            addDragDropListeners();
            // Add delete listeners
            document.querySelectorAll('.delete-task-btn').forEach(button => {
                button.addEventListener('click', async (event) => {
                    const taskId = event.target.dataset.id;
                    const confirmDelete = confirm('Are you sure you want to delete this task?');
                    if (confirmDelete) {
                        await window.aegis.deleteTask(taskId);
                        updateTaskBoard(); // Refresh board
                    }
                });
            });

        } else if (tasks.error) {
            todoTasksDiv.innerHTML = `<p class="error-text">Failed to load tasks: ${tasks.error}</p>`;
        } else {
            todoTasksDiv.innerHTML = '<p class="no-data-text">No tasks yet. Add one!</p>';
        }
    }

    function addDragDropListeners() {
        const draggables = document.querySelectorAll('.task-card');
        const columns = document.querySelectorAll('.kanban-column .task-list');

        draggables.forEach(draggable => {
            draggable.addEventListener('dragstart', () => {
                draggable.classList.add('dragging');
            });

            draggable.addEventListener('dragend', () => {
                draggable.classList.remove('dragging');
            });
        });

        columns.forEach(column => {
            column.addEventListener('dragover', (e) => {
                e.preventDefault(); // Allow drop
                const afterElement = getDragAfterElement(column, e.clientY);
                const draggable = document.querySelector('.dragging');
                if (draggable) {
                    if (afterElement == null) {
                        column.appendChild(draggable);
                    } else {
                        column.insertBefore(draggable, afterElement);
                    }
                }
            });

            column.addEventListener('drop', async (e) => {
                e.preventDefault();
                const draggable = document.querySelector('.dragging');
                if (draggable) {
                    const taskId = draggable.dataset.taskId;
                    const newStatus = column.parentElement.querySelector('h3').textContent; // Get status from column header
                    await window.aegis.updateTaskStatus(taskId, newStatus);
                    updateTaskBoard(); // Refresh board to ensure persistence
                }
            });
        });
    }

    function getDragAfterElement(column, y) {
        const draggableElements = [...column.querySelectorAll('.task-card:not(.dragging)')];
        return draggableElements.reduce((closest, child) => {
            const box = child.getBoundingClientRect();
            const offset = y - box.top - box.height / 2;
            if (offset < 0 && offset > closest.offset) {
                return { offset: offset, element: child };
            } else {
                return closest;
            }
        }, { offset: -Number.POSITIVE_INFINITY }).element;
    }

    window.aegis.promptAddTask = async (status) => {
        const description = prompt('Enter task description:');
        if (description) {
            const assignee = prompt('Assign to (e.g., RJ, Sarah):');
            if (assignee) {
                await window.aegis.addTask({ description, assignee, status });
                updateTaskBoard();
            }
        }
    };
    updateTaskBoard(); // Initial fetch

    // --- Weather Widget ---
    async function updateWeather() {
        const weather = await window.aegis.getWeather();
        if (weather && !weather.error) {
            weatherDisplayDiv.innerHTML = `<pre>${weather.content}</pre>`;
        } else {
            console.error('Failed to fetch weather:', weather.error);
            weatherDisplayDiv.innerHTML = '<p class="error-text">Failed to load weather.</p>';
        }
    }
    setInterval(updateWeather, 3600000); // Refresh every hour
    updateWeather(); // Initial fetch
});
