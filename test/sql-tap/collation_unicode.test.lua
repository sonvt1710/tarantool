#!/usr/bin/env tarantool
test = require("sqltester")
test:plan(10 * 4)

local prefix = "unicode-collation-"

local function insert_into_table(tbl_name, data)
    local sql = string.format("INSERT INTO %s VALUES ", tbl_name)
    --local values = {}
    for _, item in ipairs(data) do
        local value = "('"..item.."')"
        local e = sql .. value
        box.execute(e)
    end
end


local collation_entries =
{
    {   -- Afrikaans case sensitive
        "unicode_af_s3",
        {"a","A","á","Á","â","Â","b","B","c","C","d","D","e","E","é","É",
            "è","È","ê","Ê","ë","Ë","f","F","g","G","h","H","i","I","î","Î",
            "ï","Ï","j","J","k","K","l","L","m","M","n","N","ŉ","o","O",
            "ô","Ô","ö","Ö","p","P","q","Q","r","R","s","S","t","T","u","U",
            "û","Û","v","V","w","W","x","X","y","Y","z","Z"}},
    {
        -- Amharic
        "unicode_am_s3",
        {"ሀ","ሁ","ሂ","ሃ","ሄ","ህ","ሆ","ለ","ሉ","ሊ","ላ","ሌ","ል","ሎ","ሏ","ሐ",
            "ሑ","ሒ","ሓ","ሔ","ሕ","ሖ","ሗ","መ","ሙ","ሚ","ማ","ሜ","ም","ሞ",
            "ሟ","ሠ","ሡ","ሢ","ሣ","ሤ","ሥ","ሦ","ሧ","ረ","ሩ","ሪ","ራ","ሬ","ር",
            "ሮ","ሯ","ሰ","ሱ","ሲ","ሳ","ሴ","ስ","ሶ","ሷ","ሸ","ሹ","ሺ","ሻ","ሼ","ሽ",
            "ሾ","ሿ","ቀ","ቁ","ቂ","ቃ","ቄ","ቅ","ቆ","ቈ","ቊ","ቋ","ቌ","ቍ","በ",
            "ቡ","ቢ","ባ","ቤ","ብ","ቦ","ቧ","ቨ","ቩ","ቪ","ቫ","ቬ","ቭ","ቮ","ቯ",
            "ተ","ቱ","ቲ","ታ","ቴ","ት","ቶ","ቷ","ቸ","ቹ","ቺ","ቻ","ቼ","ች","ቾ",
            "ቿ","ኀ","ኁ","ኂ","ኃ","ኄ","ኅ","ኆ","ኈ","ኊ","ኋ","ኌ","ኍ","ነ","ኑ",
            "ኒ","ና","ኔ","ን","ኖ","ኗ","ኘ","ኙ","ኚ","ኛ","ኜ","ኝ","ኞ","ኟ","አ","ኡ",
            "ኢ","ኣ","ኤ","እ","ኦ","ኧ","ከ","ኩ","ኪ","ካ","ኬ","ክ","ኮ","ኰ","ኲ",
            "ኳ","ኴ","ኵ","ኸ","ኹ","ኺ","ኻ","ኼ","ኽ","ኾ","ወ","ዉ","ዊ","ዋ","ዌ",
            "ው","ዎ","ዐ","ዑ","ዒ","ዓ","ዔ","ዕ","ዖ","ዘ","ዙ","ዚ","ዛ","ዜ","ዝ",
            "ዞ","ዟ","ዠ","ዡ","ዢ","ዣ","ዤ","ዥ","ዦ","ዧ","የ","ዩ","ዪ","ያ",
            "ዬ","ይ","ዮ","ደ","ዱ","ዲ","ዳ","ዴ","ድ","ዶ","ዷ","ጀ","ጁ","ጂ","ጃ",
            "ጄ","ጅ","ጆ","ጇ","ገ","ጉ","ጊ","ጋ","ጌ","ግ","ጎ","ጐ","ጒ","ጓ","ጔ",
            "ጕ","ጠ","ጡ","ጢ","ጣ","ጤ","ጥ","ጦ","ጧ","ጨ","ጩ","ጪ","ጫ","ጬ",
            "ጭ","ጮ","ጯ","ጰ","ጱ","ጲ","ጳ","ጴ","ጵ","ጶ","ጷ","ጸ","ጹ","ጺ","ጻ",
            "ጼ","ጽ","ጾ","ጿ","ፀ","ፁ","ፂ","ፃ","ፄ","ፅ","ፆ","ፈ","ፉ","ፊ","ፋ","ፌ",
            "ፍ","ፎ","ፏ","ፐ","ፑ","ፒ","ፓ","ፔ","ፕ","ፖ","ፗ"}},
    {
        -- Assamese
        "unicode_as_s3",
        {"়","অ","আ","ই","ঈ","উ","ঊ","ঋ","এ","ঐ","ও","ঔ","ং ","ঁ ","ঃ ",
            "ক","খ","গ","ঘ","ঙ","চ","ছ","জ","ঝ","ঞ","ট","ঠ","ড","ড়","ঢ","ঢ়",
            "ণ","ৎ ","ত","থ","দ","ধ","ন","প","ফ","ব","ভ","ম","য","য়","ৰ",
            "ল","ৱ","শ","ষ","স","হ","ক্ষ ","া","ি","ী","ু","ূ","ৃ","ে","ৈ",
            "ো","ৌ","্"}},

    {
        -- Azerbaijani
        "unicode_az_s3",
        {"a ","A ","b ","B ","c ","C ","ç ","Ç ","ḉ ","Ḉ ","d ","D ","e ",
            "E ","ə ","Ə ","f ","F ","g ","G ","ğ ","Ğ ","ģ̆ ","Ģ̆ ","h ",
            "H ","x ","X ","ẍ ","Ẍ ","ẋ ","Ẋ ","ı ","I ","Í ","Ì ","Ĭ ",
            "Î ","Ǐ ","Ï ","Ḯ ","Ĩ ","Į ","Ī ","Ỉ ","Ȉ ","Ȋ ","Ị ","Ḭ ",
            "i ","İ ","Į̇ ","Ị̇ ","Ḭ̇ ","j ","J ","k ","K ","q ","Q ","l ",
            "L ","m ","M ","n ","N ","o ","O ","ö ","Ö ","ǫ̈ ","Ǫ̈ ","ȫ ",
            "Ȫ ","ơ̈ ","Ơ̈ ","ợ̈ ","Ợ̈ ","ọ̈ ","Ọ̈ ","p ","P ","r ","R ","s ",
            "S ","ş ","Ş ","t ","T ","u ","U ","ü ","Ü ","ǘ ","Ǘ ","ǜ ",
            "Ǜ ","ǚ ","Ǚ ","ų̈ ","Ų̈ ","ǖ ","Ǖ ","ư̈ ","Ư̈ ","ự̈ ","Ự̈ ","ụ̈ ",
            "Ụ̈ ","ṳ̈ ","Ṳ̈ ","ṷ̈ ","Ṷ̈ ","ṵ̈ ","Ṵ̈ ","v ","V ","y ","Y ","z ",
            "Z ","Ẉ","w ","W ","ẃ ","Ẃ ","ẁ ","Ẁ ","ŵ ","Ŵ ","ẘ ","ẅ ","Ẅ ",
            "ẇ ","Ẇ ","ẉ "}},
    {
        -- Belarusian
        "unicode_be_s3",
        {"а","А","б","Б","в","ᲀ","В","г","Г","д","ᲁ","Д","дж","дз","е",
            "Е","ё","Ё","ж","Ж","з","З","і","І","й","Й","к","К","л",
            "Л","м","М","н","Н","о","ᲂ","О","п","П","р","Р","с","ᲃ",
            "С","т","Т","у","У","ў","Ў","ф","Ф","х","Х","ц",
            "Ц","ч","Ч","ш","Ш","ы","Ы","ь","Ь","э","Э","ю","Ю","я","Я"}},
    {
        -- Kyrgyz
        "unicode_ky_s3",
        {"а","А","б","Б","г","Г","д","ᲁ","Д","е","Е","ё","Ё","ж","Ж",
            "з","З","и","И","й","Й","к","К","л","Л","м","М","н","Н","ң","Ң",
            "о","ᲂ","О","ө","Ө","п","П","р","Р","с","ᲃ","С","т","ᲄ",
            "Т","у","У","ү","Ү","х","Х","ч","Ч","ш","Ш","ъ","ᲆ","Ъ","ы","Ы",
            "э","Э","ю","Ю","я","Я"}},
    {
        -- Kyrgyz (russian codepage)
        "unicode_ky_s3",
        {"а","А","б","Б","в","В","г","Г","д","Д","е","Е","ё","Ё","ж","Ж",
            "з","З","и","И","й","Й","к","К","л","Л","м","М","н","Н",
            "о","О","п","П","р","Р","с","С","т","Т","у","У","ф","Ф",
            "х","Х","ц","Ц","ч","Ч","ш","Ш","щ","Щ","ъ","Ъ","ы","Ы",
            "ь","Ь","э","Э","ю","Ю","я","Я"}},
    {
        -- German (umlaut as 'ae', 'oe', 'ue')
        "unicode_de__phonebook_s3",
        {"a","A","ä","ǟ","Ǟ","ą̈","Ą̈","ạ̈","Ạ̈","ḁ̈","Ḁ̈","Ä ","b","B","c","C",
            "d","D","e","E","f","F","g","G","h","H","i","I","j","J",
            "k","K","l","L","m","M","n","N","o","O","ȫ","Ȫ","ǫ̈","Ǫ̈",
            "ơ̈","Ơ̈","ợ̈","Ợ̈","ọ̈","Ọ̈","ö ","Ö ","p","P","q","Q","r","R",
            "s","S","ss","ß","t","T","u","U","ǘ","Ǘ","ǜ","Ǜ","ǚ","Ǚ",
            "ǖ","Ǖ","ų̈","Ų̈","ư̈","Ư̈","ự̈","Ự̈","ụ̈","Ụ̈","ṳ̈","Ṳ̈","ṷ̈","Ṷ̈",
            "ṵ̈","Ṵ̈","ü ","Ü ","v","V","w","W","x","X","y","Y","z","Z"}},
    {
        -- Hebrew
        "unicode_he_s3",
        {"׳","״","א","ב","ג","ד","ה","ו","ז","ח","ט","י","כ",
            "ך","ל","מ","ם","נ","ן","ס","ע","פ","ף","צ","ץ",
            "ק","ר","ש","ת"} },
    {
        -- Japanese
        "unicode_ja_s3",
        {"幸","広","庚","康","弘","恒","慌","抗","拘","控","攻","港",
            "溝","甲","皇","硬","稿"}}
}

for _, test_entry in ipairs(collation_entries) do
    -- create title
    local extendex_prefix = string.format("%s1.%s.", prefix, test_entry[1])

    test:do_execsql_test(
        extendex_prefix.."create_table",
        string.format("create table t1(a varchar(5) collate \"%s\" primary key);", test_entry[1]),
        {})
    test:do_test(
        extendex_prefix.."insert_values",
        function()
            return insert_into_table("t1", test_entry[2])
        end, {})
    test:do_execsql_test(
        extendex_prefix.."select",
        string.format("select a from t1 order by a"),
        test_entry[2])
    test:do_execsql_test(
        extendex_prefix.."drop_table",
        "drop table t1",
        {})
end

test:finish_test()