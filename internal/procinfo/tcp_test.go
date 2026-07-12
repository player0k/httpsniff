package procinfo

import (
	"net"
	"os"
	"testing"
)

// TestLookupPIDSelf проверяет, что LookupPID по локальному порту клиентского
// сокета возвращает PID текущего процесса. Если это сломано — WinDivert-редирект
// считает все соединения чужими и ничего не перехватывает.
func TestLookupPIDSelf(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, portStr, _ := net.SplitHostPort(conn.LocalAddr().String())
	var port int
	_, err = net.ResolveTCPAddr("tcp", conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	// портируем строку в int вручную, чтобы не тянуть strconv импортом дважды
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	pid, err := LookupPID(nil, port)
	if err != nil {
		t.Fatalf("LookupPID(%d) вернул ошибку: %v", port, err)
	}
	if pid != os.Getpid() {
		t.Fatalf("LookupPID(%d) = %d, ожидался наш PID %d", port, pid, os.Getpid())
	}
}
