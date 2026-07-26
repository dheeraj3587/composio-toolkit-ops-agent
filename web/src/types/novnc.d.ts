declare module "@novnc/novnc" {
  export default class RFB {
    constructor(target: HTMLElement, url: string)

    scaleViewport: boolean
    resizeSession: boolean
    viewOnly: boolean

    disconnect(): void
    addEventListener(
      event: "connect" | "disconnect",
      callback: (event: Event) => void,
    ): void
    removeEventListener(
      event: "connect" | "disconnect",
      callback: (event: Event) => void,
    ): void
  }
}
