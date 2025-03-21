#!lua name=dialogs

local function find_dialogs(keys, args)

    local username = keys[1]
    local cursor = tonumber(args[1])
    local limit = tonumber(args[2])

    local pattern = "dialog:*" .. username .. "*"    
   -- local pattern = "*" .. "username" .. "*"
    local result = {}
    local count = 0

    repeat
        local scan_result = redis.call('SCAN', cursor, 'MATCH', pattern, 'COUNT', 10)
        cursor = tonumber(scan_result[1])
        local keys = scan_result[2]

        for i, key in ipairs(keys) do
            if count >= limit then
                break
            end

            local dialog = redis.call('HGETALL', key)
            table.insert(result, dialog)
            count = count + 1
        end
    until cursor == 0 or count >= limit

    return {cursor, result}
end

redis.register_function('find_dialogs', find_dialogs)