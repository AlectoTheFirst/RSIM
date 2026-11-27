/** Saves the answer of a GET of the API as a file with the name `name`. */
export function saveFile(url: string, name: string) {
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
}
