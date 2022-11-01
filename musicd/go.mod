module musicd

go 1.17

replace (
	github.com/DNSSEC-Provisioning/music/fsm => ../fsm
	github.com/DNSSEC-Provisioning/music/music => ../music
)

require (
	github.com/DNSSEC-Provisioning/music/music v0.0.0-00010101000000-000000000000
	github.com/go-playground/validator/v10 v10.9.0
	github.com/gorilla/mux v1.8.0
	github.com/miekg/dns v1.1.50
	github.com/spf13/viper v1.9.0
)

require (
	github.com/DNSSEC-Provisioning/music/fsm v0.0.0-20211206093248-86ccac6a2561
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-playground/locales v0.14.0 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/mattn/go-sqlite3 v1.14.9
	github.com/mitchellh/mapstructure v1.4.2 // indirect
	github.com/pelletier/go-toml v1.9.4 // indirect
	github.com/spf13/afero v1.6.0 // indirect
	github.com/spf13/cast v1.4.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5 // indirect
	golang.org/x/net v0.0.0-20210726213435-c6fcb2dbf985 // indirect
	golang.org/x/sys v0.0.0-20210823070655-63515b42dcdf // indirect
	golang.org/x/text v0.3.6 // indirect
	gopkg.in/ini.v1 v1.63.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
