package balloon

import "testing"

var password = []byte("password")

func BenchmarkBalloon256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		salt := GenerateSalt()
		BalloonHash(password, salt, 256, 32, 2)
	}
}

func BenchmarkBalloon512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		salt := GenerateSalt()
		BalloonHash(password, salt, 512, 16, 2)
	}
}
