package internal

import (
	"fmt"
	"github.com/gookit/config/v2"
	"reflect"
	"strconv"
	"strings"
)

//var (
//	defaultConfigPath = ".config/spray/"
//	defaultConfigFile = "config.yaml"
//)
//
//func LoadDefault(v interface{}) {
//	dir, err := os.UserHomeDir()
//	if err != nil {
//		logs.Log.Error(err.Error())
//		return
//	}
//	if !files.IsExist(filepath.Join(dir, defaultConfigPath, defaultConfigFile)) {
//		err := os.MkdirAll(filepath.Join(dir, defaultConfigPath), 0o700)
//		if err != nil {
//			logs.Log.Error(err.Error())
//			return
//		}
//		f, err := os.Create(filepath.Join(dir, defaultConfigPath, defaultConfigFile))
//		if err != nil {
//			logs.Log.Error(err.Error())
//			return
//		}
//		err = LoadConfig(filepath.Join(dir, defaultConfigPath, defaultConfigFile), v)
//		if err != nil {
//			logs.Log.Error(err.Error())
//			return
//		}
//		var buf bytes.Buffer
//		_, err = config.DumpTo(&buf, config.Yaml)
//		if err != nil {
//			logs.Log.Error(err.Error())
//			return
//		}
//		fmt.Println(buf.String())
//		f.Sync()
//	}
//}

func LoadConfig(filename string, v interface{}) error {
	err := config.LoadFiles(filename)
	if err != nil {
		return err
	}
	err = config.Decode(v)
	if err != nil {
		return err
	}
	return nil
}

func convertToFieldType(fieldType reflect.StructField, defaultVal string) interface{} {
	switch fieldType.Type.Kind() {
	case reflect.Bool:
		val, err := strconv.ParseBool(defaultVal)
		if err == nil {
			return val
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		val, err := strconv.ParseInt(defaultVal, 10, 64)
		if err == nil {
			return val
		}
	case reflect.Float32, reflect.Float64:
		val, err := strconv.ParseFloat(defaultVal, 64)
		if err == nil {
			return val
		}
	case reflect.String:
		return defaultVal
		// 可以根据需要扩展其他类型
	}
	return nil // 如果转换失败或类型不受支持，返回nil
}

func setFieldValue(field reflect.Value) interface{} {
	switch field.Kind() {
	case reflect.Bool:
		return false
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return 0
	case reflect.Float32, reflect.Float64:
		return 0.0
	case reflect.Slice, reflect.Array:
		return []interface{}{} // 返回一个空切片
	case reflect.String:
		return ""
	case reflect.Struct:
		return make(map[string]interface{})
	default:
		return nil
	}
}

func extractConfigAndDefaults(v reflect.Value, result map[string]interface{}, comments map[string]string) {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)
		configTag := fieldType.Tag.Get("config")
		defaultTag := fieldType.Tag.Get("default")
		descriptionTag := fieldType.Tag.Get("description") // 读取description标签

		if configTag != "" {
			var value interface{}
			if defaultTag != "" {
				value = convertToFieldType(fieldType, defaultTag)
			} else {
				value = setFieldValue(field)
			}
			fullPath := configTag // 在递归情况下，您可能需要构建完整的路径
			if field.Kind() == reflect.Struct {
				nestedResult := make(map[string]interface{})
				nestedComments := make(map[string]string)
				extractConfigAndDefaults(field, nestedResult, nestedComments)
				result[configTag] = nestedResult
				for k, v := range nestedComments {
					comments[fullPath+"."+k] = v // 保留嵌套注释的路径
				}
			} else {
				result[configTag] = value
				if descriptionTag != "" {
					comments[fullPath] = descriptionTag
				}
			}
		}
	}
}

func InitDefaultConfig(cfg interface{}, indentLevel int) string {
	var yamlStr strings.Builder
	v := reflect.ValueOf(cfg)
	if v.Kind() == reflect.Ptr {
		v = v.Elem() // 解引用指针
	}
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)
		configTag := fieldType.Tag.Get("config")
		if configTag == "" {
			continue // 忽略没有config标签的字段
		}

		defaultTag := fieldType.Tag.Get("default")
		descriptionTag := fieldType.Tag.Get("description")

		// 添加注释
		if descriptionTag != "" {
			yamlStr.WriteString(fmt.Sprintf("%s# %s\n", strings.Repeat(" ", indentLevel*2), descriptionTag))
		}

		// 准备值
		valueStr := prepareValue(fieldType.Type.Kind(), defaultTag)

		// 根据字段类型进行处理
		switch field.Kind() {
		case reflect.Struct:
			// 对于嵌套结构体，递归生成YAML
			yamlStr.WriteString(fmt.Sprintf("%s%s:\n%s", strings.Repeat(" ", indentLevel*2), configTag, InitDefaultConfig(field.Interface(), indentLevel+1)))
		default:
			// 直接生成键值对
			yamlStr.WriteString(fmt.Sprintf("%s%s: %s\n", strings.Repeat(" ", indentLevel*2), configTag, valueStr))
		}
	}

	return yamlStr.String()
}

// prepareValue 根据字段类型和default标签的值，准备最终的值字符串
func prepareValue(kind reflect.Kind, defaultVal string) string {
	if defaultVal != "" {
		return defaultVal
	}
	// 根据类型返回默认空值
	switch kind {
	case reflect.Bool:
		return "false"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "0"
	case reflect.Float32, reflect.Float64:
		return "0.0"
	case reflect.Slice, reflect.Array:
		return "[]"
	case reflect.String:
		return `""`
	case reflect.Struct, reflect.Map:
		return "{}"
	default:
		return `""`
	}
}
