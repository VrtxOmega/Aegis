'const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld(
  'api', {
    openProject: (path) => {
      window.open(path);
    }
  }
);']::[BND:NONE|RGM:SAFE|FAL:WARN]