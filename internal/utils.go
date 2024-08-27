package internal

//type bytesPatcher struct{}
//
//func (p *bytesPatcher) Visit(node *ast.Node) {
//	switch (*node).(type) {
//	case *ast.MemberNode:
//		ast.Patch(node, &ast.CallNode{
//			Callee: &ast.MemberNode{
//				Node:     *node,
//				Name:     "String",
//				Property: &ast.StringNode{Value: "String"},
//			},
//		})
//	}
//}
