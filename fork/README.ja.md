# Yumiiiiiiiiii Endstone Fork

この Fork は `https://github.com/Yumiiiiiiiiii/endstone` のソースをビルドする。
公式ソースの直接 clone や、公式 PyPI Wheel へのフォールバックは行わない。

## 現在の互換性

- upstream main / v0.11.14: BDS 1.26.52 / protocol 2193。
- 目標: BDS 1.26.60（Mojang の実配布は 1.26.60.6）。未対応。
- 1.26.60 の旧シグネチャ調査: Linux 32 / Windows 39 件が未解決。
- バージョン定数、構造体、ABI、生成済みヘッダーは未検証の値に書き換えない。
- `probe_bds.py` は解析用で、ネイティブヘッダーを生成しない。全シグネチャが一致しても ABI・実機検証合格にはならない。

## ブランチ

`main` は公式 main の追跡用、`dev` は公式更新と独自変更の統合先、
`feature/bds-1.26.60` は今回の開発、`stable` は承認済みコミット専用。
現時点の stable ブランチに検証済み Release はない。

## ビルドと実行

`Fork Linux candidate` は Fork の対象 SHA を checkout し、公式の cibuildwheel、
Conan、CMake、Ninja、Clang 20 / libc++ の構成で cp313 Linux x86-64 Wheel を生成する。
公式 manylinux ビルダーは外部依存であり、Endstone のソース取得元ではない。
バージョンは `0.11.14+ymii.g<commit>` とし、公式版と区別する。

独自ビルドの起動試験は新規 scratch world に限定し、起動、コマンド、scheduler、
停止・ワールド保存・再起動を記録する。プレイヤー接続やブロックイベント、
プライベートプラグイン、Docker、Wings の確認を代替しない。

```sh
python fork/probe_bds.py --version 1.26.60 --platform linux --output reports/probe.json
python fork/runtime_smoke.py --bds 1.26.52 --output reports/runtime.json
```

現段階では candidate artifact のみ。stable / Release / GHCR 公開は別の全項目検証ゲートを必要とする。
既存プラグインのソース、認証情報、本番 world はこの公開 Fork に含めない。
