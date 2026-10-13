# Setting up a second ESP32-C6 Thread node

1. Connect the board and find its serial port (Device Manager on Windows, e.g. `COM9`; `/dev/ttyACM*` on Linux).
2. Flash the same `ot_cli` build as the leader (ESP-IDF shell):
   ```bash
   . $IDF_PATH/export.sh            # Windows: <esp-idf>\export.ps1
   cd <workdir>/ot_cli
   idf.py -p COM9 flash
   ```
   The build auto-starts with the same dataset. If the leader is on channel 15 the node attaches by itself (as a child, possibly becoming a router later). If the leader has moved to another channel or a newer active timestamp, the node updates after attaching.
3. If it does not attach (state `detached` for more than 30 s), configure it by hand (console: `idf.py -p COM9 monitor` or a terminal with DTR/RTS off):
   ```
   ot factoryreset
   ot dataset clear
   ot dataset channel 15
   ot dataset panid <PANID>                 # e.g. 0x1234
   ot dataset extpanid <EXTPANID>           # 8 bytes hex
   ot dataset networkkey <NETWORK_KEY>      # 16 bytes hex, your own key
   ot dataset meshlocalprefix fd00:db8:a0:0::
   ot dataset networkname OpenThread-ESP
   ot dataset commit active
   ot ifconfig up
   ot thread start
   ```
   > **Note:** never publish or reuse a real network key. Create a fresh dataset on the leader (`ot dataset init new`, `ot dataset commit active`) and copy it to the node with the "Alternative" below, or substitute your own values for the `<...>` placeholders. For an isolated bench network you may use the public OpenThread demo dataset from the OpenThread documentation; do not use it on a real network.

   Alternative: on the leader run `ot dataset active -x`, then on the node `ot dataset set active <hex>`, `ot ifconfig up`, `ot thread start`.
4. Check: node `ot state` → child/router, `ot parent`; leader `ot child table` / `ot router table`; `ot ping <leader ML-EID>`.
5. To keep the node a child for the tests: `ot routereligible disable` (on the node). This makes the SED/unicast phases more predictable. Undo with `ot routereligible enable`.
