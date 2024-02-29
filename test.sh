#!/bin/bash
set -ex

meson build
ninja -C build
ninja -C build install
systemctl daemon-reload
systemctl start aux-scope-example.service
systemctl restart aux-scope-example.service
systemctl status aux-scope-workers-*.service
systemctl stop aux-scope-example.service