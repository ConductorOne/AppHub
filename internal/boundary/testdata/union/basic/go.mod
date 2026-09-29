module example.com/unionbasic

go 1.25.0

require (
	example.com/UnionMixedCase v0.0.0
	example.com/unionlocal v0.0.0
	example.com/unionwrapper v0.0.0
)

replace example.com/UnionMixedCase => ./mixedcase

replace example.com/unionlocal => ./local

replace example.com/unionwrapper => ./wrapper
