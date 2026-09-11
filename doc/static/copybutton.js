// Extract copyable text from the code block ignoring the
// prompts and output.
function getCopyableText(rootElement) {
    rootElement = rootElement.cloneNode(true)
    // tracebacks (.gt) contain bare text elements that
    // need to be removed
    const tracebacks = rootElement.querySelectorAll(".gt")
    for (const el of tracebacks) {
        while (
            el.nextSibling &&
            (el.nextSibling.nodeType !== Node.ELEMENT_NODE ||
                !el.nextSibling.matches(".gp, .go"))
        ) {
            el.nextSibling.remove()
        }
    }
    // Remove all elements with the "go" (Generic.Output),
    // "gp" (Generic.Prompt), or "gt" (Generic.Traceback) CSS class
    const elements = rootElement.querySelectorAll(".gp, .go, .gt, .linenos")
    for (const el of elements) {
        el.remove()
    }
    return rootElement.innerText.trim()
}

const loadCopyButton = () => {
    const button = document.createElement("button")
    button.classList.add("copybutton")
    button.type = "button"
    button.innerText = _("Copy")
    button.title = _("Copy to clipboard")

    const makeOnButtonClick = () => {
        let timeout = null
        // define the behavior of the button when it's clicked
        return async event => {
            // check if the clipboard is available
            if (!navigator.clipboard || !navigator.clipboard.writeText) {
                return;
            }

            clearTimeout(timeout)
            const buttonEl = event.currentTarget
            const codeEl = buttonEl.nextElementSibling

            try {
                await navigator.clipboard.writeText(getCopyableText(codeEl))
            } catch (e) {
                console.error(e.message)
                return
            }

            buttonEl.innerText = _("Copied!")
            timeout = setTimeout(() => {
                buttonEl.innerText = _("Copy")
            }, 1500)
        }
    }

    const highlightedElements = document.querySelectorAll(
        ".highlight-python .highlight,"
        + ".highlight-python3 .highlight,"
        + ".highlight-pycon .highlight,"
        + ".highlight-pycon3 .highlight,"
        + ".highlight-bash .highlight,"
        + ".highlight-console .highlight,"
        + ".highlight-doscon .highlight,"
        + ".highlight-ps1con .highlight,"
        + ".highlight-sh .highlight,"
        + ".highlight-shell-session .highlight,"
        + ".highlight-default .highlight"
    )

    // create and add the button to all the code blocks that contain >>>
    highlightedElements.forEach(el => {
        el.style.position = "relative"

        // if we find a console prompt (.gp), prepend the (deeply cloned) button
        const clonedButton = button.cloneNode(true)
        // the onclick attribute is not cloned, set it on the new element
        clonedButton.onclick = makeOnButtonClick()
        el.prepend(clonedButton)
    })
}

if (document.readyState !== "loading") {
    loadCopyButton()
} else {
    document.addEventListener("DOMContentLoaded", loadCopyButton)
}
