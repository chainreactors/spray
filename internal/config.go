package internal

import (
	"fmt"
	"github.com/goccy/go-yaml"
	"github.com/gookit/config/v2"
	"reflect"
	"strconv"
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

// extractConfigAndDefaults 提取带有 `config` 和 `default` 标签的字段
func extractConfigAndDefaults(v reflect.Value, result map[string]interface{}) {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := t.Field(i)
		configTag := fieldType.Tag.Get("config")
		defaultTag := fieldType.Tag.Get("default")

		if configTag != "" {
			var value interface{}
			if defaultTag != "" {
				value = convertToFieldType(fieldType, defaultTag)
			} else {
				value = setFieldValue(field)
			}
			if field.Kind() == reflect.Struct {
				nestedResult := make(map[string]interface{})
				extractConfigAndDefaults(field, nestedResult)
				result[configTag] = nestedResult
			} else {
				result[configTag] = value
			}
		}
	}
}

func initDefaultConfig(cfg interface{}) (string, error) {
	v := reflect.ValueOf(cfg)
	if v.Kind() != reflect.Struct {
		return "", fmt.Errorf("expected a struct, got %s", v.Kind())
	}

	result := make(map[string]interface{})
	extractConfigAndDefaults(v, result)

	yamlData, err := yaml.Marshal(result)
	if err != nil {
		return "", err
	}

	return string(yamlData), nil
}
