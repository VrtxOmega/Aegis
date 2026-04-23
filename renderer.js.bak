document.addEventListener('DOMContentLoaded', async () => {
    const updateSystemStatus = async () => {
        const data = await window.aegis.getSystemStatus();
        if (data && !data.error) {
            document.getElementById('cpu').innerText = `CPU: ${data.cpu}%`;
            document.getElementById('ram').innerText = `RAM: ${data.ram_percent}% (${(data.ram_used / (1024**3)).toFixed(2)} GB / ${(data.ram_total / (1024**3)).toFixed(2)} GB)`;
            document.getElementById('disk').innerText = `Disk: ${data.disk_percent}% (${(data.disk_used / (1024**3)).toFixed(2)} GB / ${(data.disk_total / (1024**3)).toFixed(2)} GB)`;
        } else {
            console.error('Error fetching system status:', data ? data.error : 'No data');
            document.getElementById('cpu').innerText = `CPU: Error`;
            document.getElementById('ram').innerText = `RAM: Error`;
            document.getElementById('disk').innerText = `Disk: Error`;
        }
    };

    const loadProjects = async () => {
        const projects = await window.aegis.getProjects();
        const projectListDiv = document.getElementById('project-list');
        projectListDiv.innerHTML = '';
        if (projects && !projects.error) {
            projects.forEach(project => {
                const button = document.createElement('button');
                button.innerText = project.name;
                button.onclick = () => window.aegis.openProjectFolder(project.path);
                projectListDiv.appendChild(button);
            });
        } else {
            console.error('Error fetching projects:', projects ? projects.error : 'No data');
            projectListDiv.innerText = 'Failed to load projects.';
        }
    };

    const renderTasks = (tasks) => {
        const todoColumn = document.getElementById('todo-column');
        const inProgressColumn = document.getElementById('in-progress-column');
        const doneColumn = document.getElementById('done-column');

        todoColumn.innerHTML = '';
        inProgressColumn.innerHTML = '';
        doneColumn.innerHTML = '';

        if (tasks && !tasks.error) {
            tasks.forEach(task => {
                const card = document.createElement('div');
                card.className = 'kanban-card';
                card.innerText = task.task;
                if (task.status === 'todo') {
                    todoColumn.appendChild(card);
                } else if (task.status === 'inprogress') {
                    inProgressColumn.appendChild(card);
                } else if (task.status === 'done') {
                    doneColumn.appendChild(card);
                }
            });
        } else {
            console.error('Error rendering tasks:', tasks ? tasks.error : 'No data');
            todoColumn.innerText = 'Failed to load tasks.';
        }
    };

    const loadTasks = async () => {
        const tasks = await window.aegis.getTasks();
        renderTasks(tasks);
    };

    const loadWeather = async () => {
        const weather = await window.aegis.getWeather();
        if (weather && !weather.error && weather.current_condition && weather.nearest_area) {
            document.getElementById('weather-location').innerText = `Location: ${weather.nearest_area[0].areaName[0].value}, ${weather.nearest_area[0].region[0].value}`;
            document.getElementById('weather-temp').innerText = `Temperature: ${weather.current_condition[0].temp_F}°F`;
            document.getElementById('weather-desc').innerText = `Conditions: ${weather.current_condition[0].weatherDesc[0].value}`;
            document.getElementById('weather-wind').innerText = `Wind: ${weather.current_condition[0].windspeedMiles} mph`;
        } else {
            console.error('Error fetching weather:', weather ? weather.error : 'No data');
            document.getElementById('weather-location').innerText = 'Weather: Error';
            document.getElementById('weather-temp').innerText = '';
            document.getElementById('weather-desc').innerText = '';
            document.getElementById('weather-wind').innerText = '';
        }
    };

    // Initial loads
    updateSystemStatus();
    loadProjects();
    loadTasks();
    loadWeather();

    // Auto-refresh
    setInterval(updateSystemStatus, 5000);
    setInterval(loadTasks, 10000);
    setInterval(loadWeather, 600000); // Every 10 minutes

    // Add Task Form Submission
    document.getElementById('add-task-form').addEventListener('submit', async (event) => {
        event.preventDefault();
        const taskInput = document.getElementById('task-input');
        const assigneeSelect = document.getElementById('assignee-select');
        const task = taskInput.value;
        const status = assigneeSelect.value;

        if (task) {
            const result = await window.aegis.addTask(task, status);
            if (result && result.status === 'success') {
                taskInput.value = '';
                loadTasks(); // Refresh tasks after adding
            } else {
                console.error('Failed to add task:', result ? result.error : 'Unknown error');
                alert('Failed to add task: ' + (result ? result.error : 'Unknown error'));
            }
        }
    });
});