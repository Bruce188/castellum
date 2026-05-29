import '@testing-library/jest-dom';

// jsdom's Blob implementation does not include .text() / .arrayBuffer() (part of the
// File API Living Standard).  Polyfill them so tests that call blob.text() pass in the
// jsdom environment without relying on the browser's native Blob.
if (typeof Blob !== 'undefined' && typeof Blob.prototype.text !== 'function') {
  Blob.prototype.text = function (): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = () => reject(reader.error);
      reader.readAsText(this);
    });
  };
}
