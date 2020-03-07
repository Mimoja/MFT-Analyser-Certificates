package main

import (
	"github.com/Mimoja/MFT-Common"
	"encoding/json"
)

var Bundle MFTCommon.AppBundle

func main() {
	Bundle = MFTCommon.Init("CryptoFetcher")

	setupYara()

	Bundle.MessageQueue.FlashImagesQueue.RegisterCallback("CryptoFetcher", func(payload string) error {

		Bundle.Log.Debugf("Got new Message!")
		var file MFTCommon.FlashImage
		err := json.Unmarshal([]byte(payload), &file)
		if err != nil {
			Bundle.Log.Errorf("Could not unmarshall json: %v", err)
			return err;
		}

		return analyse(file)
	})
	Bundle.Log.Info("Starting up!")
	select {}
}
