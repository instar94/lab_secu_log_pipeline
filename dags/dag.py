from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import pandas as pd
from airflow.decorators import dag, task
from pendulum import datetime

DATA_RAW = Path("/opt/airflow/data/raw")
DATA_PROCESSED = Path("/opt/airflow/data/processed")

RAW_FILES = [
    DATA_RAW / "Monday-WorkingHours.pcap_ISCX.csv",
    DATA_RAW / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

EXPECTED_COLUMN_COUNT = 79  # 78개 특징 + Label


@dag(
    dag_id="cicids2017_etl",
    description="CICIDS2017 Monday+Friday-DDoS 추출-정제-저장 파이프라인",
    schedule=None,  # 정기 실행 없이 수동 트리거만
    start_date=datetime(2026, 1, 1),
    catchup=False,
    tags=["cicids2017", "portfolio"],
)
def cicids2017_etl():

    @task
    def extract_and_validate() -> str:
        """원본 CSV 2개를 읽어 스키마를 검증하고, 합친 결과를 중간 파일로 저장한다."""
        frames = []
        for path in RAW_FILES:
            if not path.exists():
                raise FileNotFoundError(f"원본 파일 없음: {path}")
            df = pd.read_csv(path)
            df.columns = df.columns.str.strip()
            if df.shape[1] != EXPECTED_COLUMN_COUNT:
                raise ValueError(
                    f"{path.name}: 컬럼 {df.shape[1]}개, 예상 {EXPECTED_COLUMN_COUNT}개"
                )
            frames.append(df)

        df = pd.concat(frames, ignore_index=True)
        logging.info("extract_and_validate: %s행 %s열", *df.shape)

        DATA_PROCESSED.mkdir(parents=True, exist_ok=True)
        out_path = DATA_PROCESSED / "_extracted.parquet"
        df.to_parquet(out_path, index=False)
        return str(out_path)

    @task
    def transform_clean(extracted_path: str) -> str:
        """EDA에서 확정한 규칙대로 정제한다."""
        df = pd.read_parquet(extracted_path)
        before = len(df)

        if "Fwd Header Length.1" in df.columns:
            df = df.drop(columns=["Fwd Header Length.1"])

        # 규칙 1: Duration=0 → Inf/NaN을 0으로 치환 + 플래그
        df["is_zero_duration"] = df["Flow Duration"] == 0
        df["Flow Bytes/s"] = df["Flow Bytes/s"].replace([np.inf, -np.inf], 0).fillna(0)
        df["Flow Packets/s"] = df["Flow Packets/s"].replace([np.inf, -np.inf], 0)

        # 규칙 2: Duration<0 삭제
        df = df[df["Flow Duration"] >= 0]

        # 규칙 3: Header Length류 극단값 삭제
        broken = (
            (df["Fwd Header Length"] < 0)
            | (df["Bwd Header Length"] < 0)
            | (df["min_seg_size_forward"] < 0)
        )
        df = df[~broken]

        # 규칙 5: 완전 중복 삭제
        df = df.drop_duplicates()

        logging.info(
            "transform_clean: %s행 → %s행 (%s행 제거)",
            before,
            len(df),
            before - len(df),
        )

        out_path = DATA_PROCESSED / "_cleaned.parquet"
        df.to_parquet(out_path, index=False)
        return str(out_path)

    @task
    def load(cleaned_path: str) -> None:
        """정제 결과를 최종 파일명으로 저장한다."""
        df = pd.read_parquet(cleaned_path)
        final_path = DATA_PROCESSED / "cicids2017_clean.parquet"
        df.to_parquet(final_path, index=False)
        logging.info("load: %s행을 %s에 저장", len(df), final_path)

    load(transform_clean(extract_and_validate()))


cicids2017_etl()
