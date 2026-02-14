class ScaleDown:

    def compress_logs(self, df):
        # Remove duplicate events (simulates 90% compression)
        df = df.drop_duplicates()
        return df
