package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func generateKey() []byte {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		fmt.Println("Ошибка генерации ключа:", err)
		return nil
	}
	return key
}

func InitUI(w fyne.Window) {

	bgImage := canvas.NewImageFromFile("assets/background.png")
	bgImage.FillMode = canvas.ImageFillStretch

	icon, err := fyne.LoadResourceFromPath("assets/icon.ico")
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		w.SetIcon(icon)
	}

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("                        Enter a password       ")

	smallPasswordEntry := container.NewCenter(
		container.NewGridWrap(fyne.NewSize(300, 40), passwordEntry),
	)

	abonentOptions := make([]string, 256)
	for i := 1; i <= 256; i++ {
		abonentOptions[i-1] = fmt.Sprintf("%d", i)
	}

	abonentCount := widget.NewSelect(abonentOptions, nil)
	abonentCount.PlaceHolder = "Select abonent count"

	smallAbonentCount := container.NewHBox(
		layout.NewSpacer(),
		container.NewGridWrap(fyne.NewSize(150, 40), abonentCount),
		layout.NewSpacer(),
	)

	keyOutput := widget.NewMultiLineEntry()
	keyOutput.SetPlaceHolder("Generated keys will appear here...")
	keyOutput.Disable()
	keyOutput.Wrapping = fyne.TextWrapWord
	keyOutput.Scroll = container.ScrollBoth

	iconGenKey, err := fyne.LoadResourceFromPath("assets/save_button.png")
	if err != nil {
		fmt.Println("Ошибка загрузки иконки:", err)
		iconGenKey = theme.ConfirmIcon()
	}

	generateKeyButton := widget.NewButtonWithIcon(
		"Generate keys",
		iconGenKey,
		func() {
			password := passwordEntry.Text
			if password == "" {
				dialog.ShowInformation("Error", "Enter a password!", w)
				return
			}

			countStr := abonentCount.Selected
			count, err := strconv.Atoi(countStr)
			if err != nil {
				dialog.ShowInformation("Error", "Select a valid abonent count!", w)
				return
			}

			var keys [][]byte
			keysText := ""
			for i := 0; i < count; i++ {
				key := generateKey()
				if key == nil {
					dialog.ShowInformation("Error", "Key generation failed!", w)
					return
				}
				keys = append(keys, key)
				keysText += fmt.Sprintf("Key %d: %s\n", i+1, hex.EncodeToString(key))
			}

			keyOutput.SetText(keysText)

			saveDialog := dialog.NewFileSave(
				func(writer fyne.URIWriteCloser, err error) {
					if err != nil || writer == nil {
						dialog.ShowInformation("Error", "File save canceled or failed!", w)
						return
					}
					defer writer.Close()

					for _, key := range keys {
						_, err := writer.Write(key)
						if err != nil {
							dialog.ShowInformation("Error", "Failed to write keys!", w)
							return
						}
					}

					dialog.ShowInformation("Success", "Keys saved successfully!", w)
				}, w)

			saveDialog.SetFileName("Qalqan_keys.bin")
			saveDialog.Show()
		},
	)

	centeredGenerateKeyButton := container.NewCenter(generateKeyButton)

	mainUI := container.NewVBox(
		widget.NewLabel(" "),
		smallPasswordEntry,
		container.NewCenter(widget.NewLabel("Select number of abonents:")),
		smallAbonentCount,
		centeredGenerateKeyButton,
		keyOutput,
	)

	content := container.NewStack(bgImage, mainUI)
	w.SetContent(content)
}
