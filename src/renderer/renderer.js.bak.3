document.addEventListener('DOMContentLoaded', async () => {
    const cpuUsageElem = document.getElementById('cpu-usage');
    const ramUsageElem = document.getElementById('ram-usage');
    const diskUsageElem = document.getElementById('disk-usage');
    const projectListElem = document.getElementById('project-list');
    const todoTasksElem = document.getElementById('todo-tasks');
    const inProgressTasksElem = document.getElementById('in-progress-tasks');
    const doneTasksElem = document.getElementById('done-tasks');
    const weatherConditionElem = document.getElementById('weather-condition');
    const weatherTempElem = document.getElementById('weather-temp');
    const addTaskBtn = document.getElementById('add-task-btn');

    // --- System Status ---
    const updateSystemStatus = async () => {
        try {
            const status = await window.aegisAPI.getSystemStatus();
            cpuUsageElem.textContent = status.cpu;
            ramUsageElem.textContent = status.ram;
            diskUsageElem.textContent = status.disk;
        } catch (error) {
            console.error('Failed to fetch system status:', error);
            cpuUsageElem.textContent = 'Error';
            ramUsageElem.textContent = 'Error';
            diskUsageElem.textContent = 'Error';
        }
    };
    setInterval(updateSystemStatus, 5000); // Refresh every 5 seconds
    updateSystemStatus(); // Initial fetch

    // --- Project Launcher ---
    const updateProjectList = async () => {
        try {
            const projects = await window.aegisAPI.getProjects();
            projectListElem.innerHTML = ''; // Clear existing list
            if (projects.length === 0) {
                projectListElem.innerHTML = '<p>No projects found.</p>';
                return;
            }
            projects.forEach(project => {
                const projectDiv = document.createElement('div');
                projectDiv.className = 'project-item'; // Add a class for styling
                projectDiv.innerHTML = `
                    <h3>${project.name}</h3>
                    <p>${project.path}</p>
                    <button data-path="${project.path}">Open Folder</button>
                `;
                projectListElem.appendChild(projectDiv);
            });
            // Add event listeners for buttons
            projectListElem.querySelectorAll('button').forEach(button => {
                button.addEventListener('click', async (event) => {
                    const projectPath = event.target.dataset.path;
                    const result = await window.aegisAPI.openProjectFolder(projectPath);
                    if (!result.success) {
                        console.error(result.message);
                        alert(`Failed to open folder: ${result.message}`);
                    }
                });
            });
        } catch (error) {
            console.error('Failed to fetch projects:', error);
            projectListElem.innerHTML = '<p>Error loading projects.</p>';
        }
    };
    updateProjectList(); // Initial fetch

    // --- Family Task Board ---
    const renderTasks = (tasks) => {
        todoTasksElem.innerHTML = '';
        inProgressTasksElem.innerHTML = '';
        doneTasksElem.innerHTML = '';

        tasks.forEach(task => {
            const taskItem = document.createElement('div');
            taskItem.className = 'task-item';
            taskItem.draggable = true; // Make tasks draggable
            taskItem.dataset.taskId = task.id;
            taskItem.dataset.taskStatus = task.status;
            taskItem.innerHTML = `
                <h4>${task.title}</h4>
                <p>Assigned to: ${task.assignedTo}</p>
                <p>Due: ${task.dueDate}</p>
                <button class="delete-task-btn" data-id="${task.id}">Delete</button>
            `;
            if (task.status === 'todo') {
                todoTasksElem.appendChild(taskItem);
            } else if (task.status === 'in-progress') {
                inProgressTasksElem.appendChild(taskItem);
            } else if (task.status === 'done') {
                doneTasksElem.appendChild(taskItem);
            }
        });

        // Add drag and drop listeners
        document.querySelectorAll('.task-item').forEach(item => {
            item.addEventListener('dragstart', (e) => {
                e.dataTransfer.setData('text/plain', e.target.dataset.taskId);
                e.dataTransfer.effectAllowed = 'move';
            });
        });

        document.querySelectorAll('.task-list').forEach(list => {
            list.addEventListener('dragover', (e) => {
                e.preventDefault(); // Allow drop
                e.dataTransfer.dropEffect = 'move';
            });

            list.addEventListener('drop', async (e) => {
                e.preventDefault();
                const taskId = e.dataTransfer.getData('text/plain');
                const newStatus = list.id.replace('-tasks', ''); // e.g., 'todo' from 'todo-tasks'
                
                if (taskId) {
                    const result = await window.aegisAPI.updateTask(parseInt(taskId), { status: newStatus });
                    if (result.error) {
                        console.error('Failed to update task status:', result.error);
                        alert('Failed to update task status.');
                    } else {
                        updateTaskBoard(); // Refresh the board
                    }
                }
            });
        });

        // Add delete button listeners
        document.querySelectorAll('.delete-task-btn').forEach(button => {
            button.addEventListener('click', async (e) => {
                const taskId = parseInt(e.target.dataset.id);
                if (confirm('Are you sure you want to delete this task?')) {
                    const result = await window.aegisAPI.deleteTask(taskId);
                    if (result.error) {
                        console.error('Failed to delete task:', result.error);
                        alert('Failed to delete task.');
                    } else {
                        updateTaskBoard(); // Refresh the board
                    }
                }
            });
        });
    };

    const updateTaskBoard = async () => {
        try {
            const tasks = await window.aegisAPI.getTasks();
            renderTasks(tasks);
        } catch (error) {
            console.error('Failed to fetch tasks:', error);
            todoTasksElem.innerHTML = '<p>Error loading tasks.</p>';
            inProgressTasksElem.innerHTML = '<p>Error loading tasks.</p>';
            doneTasksElem.innerHTML = '<p>Error loading tasks.</p>';
        }
    };
    updateTaskBoard(); // Initial fetch

    addTaskBtn.addEventListener('click', async () => {
        const title = prompt('Enter task title:');
        if (title) {
            const assignedTo = prompt('Assign to (optional):', 'Unassigned');
            const dueDate = prompt('Due Date (optional, e.g., YYYY-MM-DD):', 'No Date');
            const result = await window.aegisAPI.addTask({ title, assignedTo, dueDate, status: 'todo' });
            if (result.error) {
                console.error('Failed to add task:', result.error);
                alert('Failed to add task.');
            } else {
                updateTaskBoard(); // Refresh the board
            }
        }
    });

    // --- Weather Widget ---
    const updateWeather = async () => {
        try {
            const weather = await window.aegisAPI.getWeather();
            weatherConditionElem.textContent = weather.condition;
            weatherTempElem.textContent = weather.temperature;
        } catch (error) {
            console.error('Failed to fetch weather:', error);
            weatherConditionElem.textContent = 'Error';
            weatherTempElem.textContent = 'Error';
        }
    };
    setInterval(updateWeather, 300000); // Refresh every 5 minutes
    updateWeather(); // Initial fetch
});
