Expected output for each repro once plan 295 is fixed.

01_but_if_append_discards_rest.vox
    BEFORE
    AFTER
    SECOND AFTER
  (and `line` contains "#", since v is 1)

02_function_tail_escapes.vox
    MAIN
  ('do thing' is never called, so nothing from its body may run)

03_loop_tail_ejected.vox
    EXTRA k=1
    BRANCH k=1
    TAIL k=1
    EXTRA k=2
    TAIL k=2
