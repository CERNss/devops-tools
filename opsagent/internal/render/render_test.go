package render

import "testing"

func TestTemplateReplacesSupportedPlaceholders(t *testing.T) {
	got, err := Template("image={{IMAGE}}\nname=${APP_NAME}\n", map[string]string{
		"APP_NAME": "demo",
		"IMAGE":    "nginx:latest",
	})
	if err != nil {
		t.Fatal(err)
	}

	want := "image=nginx:latest\nname=demo\n"
	if got != want {
		t.Fatalf("template mismatch: want %q, got %q", want, got)
	}
}

func TestEnvSortsAndQuotesValues(t *testing.T) {
	got, err := Env("", map[string]string{
		"Z_VALUE": "plain",
		"A_VALUE": "hello world",
		"EMPTY":   "",
	})
	if err != nil {
		t.Fatal(err)
	}

	want := "A_VALUE=\"hello world\"\nEMPTY=\"\"\nZ_VALUE=plain\n"
	if got != want {
		t.Fatalf("env mismatch:\nwant:\n%s\ngot:\n%s", want, got)
	}
}
