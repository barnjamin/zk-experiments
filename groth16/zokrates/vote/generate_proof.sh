
 #!/bin/bash
 
 set -eu
 
 PASSPHRASE="808464432 808464432 808464432 808464432 808464432 808464432 808464432 808464432 808464432 808464432 808464432 808464432 808464432 808464432 1684365668 1650812262"
 
 MEMBER_ONE_PHRASE_HASH="1137940615 2505198337 2156529772 3244891054 2804562915 3418232704 885281992 1003777860"
 MEMBER_TWO_PHRASE_HASH="150691715 614202410 3578829323 894527213 4051470970 2408576571 3581241564 286896087"
 MEMBER_PHRASES="$MEMBER_ONE_PHRASE_HASH $MEMBER_TWO_PHRASE_HASH"
 
 zokrates compute-witness --verbose -a $PASSPHRASE $MEMBER_PHRASES
 
 zokrates generate-proof
 