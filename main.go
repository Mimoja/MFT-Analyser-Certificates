package main

import (
	"MimojaFirmwareToolkit/pkg/Common"
	"encoding/json"
)

const NumberOfWorker = 1

func worker(id int, file <-chan MFTCommon.FlashImage) {

	for true {
		entry := <-file
		Bundle.Log.Infof("Handeling %s in Worker %d\n", entry.ID.GetID(), id)
		analyse(entry)
	}
}

var Bundle MFTCommon.AppBundle

func main() {
	Bundle = MFTCommon.Init("CryptoFetcher")

	setupYara()

	entries := make(chan MFTCommon.FlashImage, NumberOfWorker)
	for w := 1; w <= NumberOfWorker; w++ {
		go worker(w, entries)
	}

	Bundle.MessageQueue.FlashImagesQueue.RegisterCallback("CryptoFetcher", func(payload string) error {

		Bundle.Log.Debugf("Got new Message!")
		var file MFTCommon.FlashImage
		err := json.Unmarshal([]byte(payload), &file)
		if err != nil {
			Bundle.Log.Errorf("Could not unmarshall json: %v", err)
		}

		entries <- file

		return err
	})
	Bundle.Log.Info("Starting up!")
	select {}
}
