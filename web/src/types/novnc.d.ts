declare module "@novnc/novnc" {
  /** The remote clipboard payload noVNC emits for an RFB ServerCutText message. */
  export interface RfbClipboardEvent extends Event {
    detail: { text: string }
  }

  export default class RFB {
    constructor(target: HTMLElement, url: string)

    scaleViewport: boolean
    resizeSession: boolean
    viewOnly: boolean

    /** Send text to the remote X clipboard (RFB ClientCutText). */
    clipboardPasteFrom(text: string): void

    /** Synthesize a key event inside the remote session. */
    sendKey(keysym: number, code: string, down?: boolean): void

    disconnect(): void
    addEventListener(
      event: "connect" | "disconnect",
      callback: (event: Event) => void,
    ): void
    addEventListener(
      event: "clipboard",
      callback: (event: RfbClipboardEvent) => void,
    ): void
    removeEventListener(
      event: "connect" | "disconnect",
      callback: (event: Event) => void,
    ): void
    removeEventListener(
      event: "clipboard",
      callback: (event: RfbClipboardEvent) => void,
    ): void
  }
}
