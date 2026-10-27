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

## Pythonプラグイン読み込みの修正

仮想環境のPythonをsymlink解決してしまうとbase interpreterが選ばれ、依存関係が外れるため、
指定されたvenvのパスを保持する。新規prefixへWheelをインストールした直後は検索キャッシュを
無効化し、以前の「ディレクトリが存在しない」という記録でimportが失敗する問題を直す。
pip失敗時は古いmetadataを読み込まず停止する。回帰試験は`tests/test_python_plugin_loader.py`。

## 更新と昇格

`Fork upstream and BDS monitor`は公式mainのSHAとMojangの配布版を記録する。
未対応BDSを検出すると本人ForkにIssueを記録する（既存のopen Issueがあれば重複作成しない）。
ソースの取り込みは`propose_sync`を指定した時だけ行い、upstreamの変更をForkの別ブランチへmergeし、
dev向けPRを作る。競合は本人ForkのIssueに記録し、stableへ直接mergeしない。
GitHub標準tokenで作ったPRは後続CIを自動起動しないため、同期処理がFork candidateを明示実行する。
定期実行・手動実行の定義をGitHubが見つけられるよう、運用時のdefault branchは`dev`に設定する。
`main`は公式追跡用として残す。

`Fork validated release promotion`は手動実行専用。実行前にGitHubのEnvironment
`stable-promotion`へ必須レビュアーを設定する。Environment名を書くだけでは承認制にならない。
未設定のまま本番の公開権限を渡さない。

昇格には成功したFork CI run、同じcommit、同じWheel SHA256、同じBDS archive SHA256を要求し、
native ABI、起動、コマンド、scheduler、保存と再起動、プレイヤーイベント、ブロック・エンティティ、
ネットワーク、プラグイン、Docker、Wingsの全項目の実機証拠ファイルを照合する。
現在のCIにはプレイヤー/Wings実機試験を行う環境がないため、full-runtime-evidence artifactは未生成。
候補Wheelのビルドが成功しても、この不足で昇格は停止する。

合格時だけ不変の`ymii-*` Releaseを作り、stableブランチをfast-forwardし、
stable Releaseのmanifestエイリアスを更新する。公式PyPIへは公開しない。
実行ログ・プライベートデータはReleaseへ添付せず、公開するのはWheel、manifest、検証項目と証拠ハッシュのみ。

Egg Forkの`Promote tested Wings image`は同じ実機証拠に記載されたGHCR digestをstableへ付け替える。
再ビルドした別イメージを合格済みとして公開しない。

1.26.60のABI修正には32個のLinux未解決フックと3個の曖昧一致の解析、構造体・virtual table・
関数引数の再検証が必要。旧版は82個すべて一意に解決する比較試験に合格している。
`fork/diagnostics`の結果は実バイナリから取得したもので、互換性の宣言ではない。
