package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Qalqan_QG")
	myWindow.Resize(fyne.NewSize(350, 325))
	myWindow.CenterOnScreen()
	myWindow.SetFixedSize(false)
	InitUI(myWindow)
	myWindow.ShowAndRun()
}
