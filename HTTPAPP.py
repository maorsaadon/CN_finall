from flask import Flask, request, send_file
from pytube import YouTube
from moviepy.editor import *
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor

app = Flask(__name__)

class FileDownloadProtocol(Protocol):
    def connectionMade(self):
        self.buffer = b''

    def dataReceived(self, data):
        self.buffer += data

    def connectionLost(self, reason):
        # Extract the URL from the request data
        request_data = self.buffer.decode('utf-8')
        url = request_data.split('url=')[1]

        # Download the YouTube video
        yt = YouTube(url)
        video = yt.streams.first()
        video.download()

        # Convert the video to an MP3 audio file
        video_path = f"{yt.title}.mp4"
        audio_path = f"{yt.title}.mp3"
        video_clip = VideoFileClip(video_path)
        audio_clip = video_clip.audio
        audio_clip.write_audiofile(audio_path)

        # Send the MP3 audio file to the client
        with open(audio_path, 'rb') as f:
            self.transport.write(f.read())
            self.transport.loseConnection()

class FileDownloadFactory(Factory):
    def buildProtocol(self, addr):
        return FileDownloadProtocol()

# Listen on TCP port 8000
reactor.listenTCP(8000, app)

# Listen on RUDP port 8000
reactor.listenWith(FileDownloadFactory(), 8000, 'localhost', interface='0.0.0.0', protoName='rudp')

if __name__ == '__main__':
    reactor.run()
