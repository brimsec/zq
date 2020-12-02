package api

type WorkerAddr struct {
	Addr string `json:"addr"`
}

type UnreserveRequest struct {
	Addrs []string `json:"addrs"`
}

type UnreserveResponse struct {
	Reserved bool `json:"reserved"`
}

type DeregisterRequest struct {
	WorkerAddr
}

type Worker struct {
	WorkerAddr
	NodeName string `json:"node"`
}

type RegisterRequest struct {
	Worker
}

type RegisterResponse struct {
	Registered bool `json:"registered"`
}

type RecruitRequest struct {
	NumberRequested int `json:"N"`
}

type RecruitResponse struct {
	Workers []Worker `json:"workers"`
}

type WorkersStatsResponse struct {
	LenFreePool     int `json:"LenFreePool"`
	LenReservedPool int `json:"LenReservedPool"`
	LenNodePool     int `json:"LenNodePool"`
}