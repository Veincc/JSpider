package apidiscovery

func cloneHeaders(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for name, value := range values {
		cloned[name] = value
	}
	return cloned
}

func cloneGraphQL(info *GraphQLInfo) *GraphQLInfo {
	if info == nil {
		return nil
	}
	return &GraphQLInfo{
		OperationName: info.OperationName,
		Variables:     cloneStrings(info.Variables),
	}
}

func cloneStaticEndpoint(endpoint StaticEndpoint) StaticEndpoint {
	endpoint.Headers = cloneHeaders(endpoint.Headers)
	endpoint.QueryParams = cloneParameters(endpoint.QueryParams)
	endpoint.BodyParams = cloneParameters(endpoint.BodyParams)
	return endpoint
}

func cloneStaticEndpoints(endpoints []StaticEndpoint) []StaticEndpoint {
	if len(endpoints) == 0 {
		return nil
	}
	cloned := make([]StaticEndpoint, len(endpoints))
	for index := range endpoints {
		cloned[index] = cloneStaticEndpoint(endpoints[index])
	}
	return cloned
}

func cloneRuntimeRequest(request RuntimeRequest) RuntimeRequest {
	request.Headers = cloneHeaders(request.Headers)
	request.QueryParams = cloneParameters(request.QueryParams)
	request.BodyParams = cloneParameters(request.BodyParams)
	request.GraphQL = cloneGraphQL(request.GraphQL)
	request.Initiator.StackURLs = cloneStrings(request.Initiator.StackURLs)
	return request
}

func cloneRuntimeRequests(requests []RuntimeRequest) []RuntimeRequest {
	if len(requests) == 0 {
		return nil
	}
	cloned := make([]RuntimeRequest, len(requests))
	for index := range requests {
		cloned[index] = cloneRuntimeRequest(requests[index])
	}
	return cloned
}
